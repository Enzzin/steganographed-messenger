"""Chat bidirecional com dados codificados no primeiro byte de pacotes ICMP."""

from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
import math
from pathlib import Path
import queue
import re
import secrets
import socket
import struct
import threading
import time
import uuid
import zlib


ICMP_HEADER = struct.Struct("!BBHHH")
FRAME_PREFIX = struct.Struct("!4s16s16sBH")
FRAME_HEADER = struct.Struct("!4s16s16sBHI")
MAGIC = b"SMC1"
TEXT, FILE = 1, 2
START, END, ACK = 0x9B, 0xDB, 0xFB
MAX_FRAME_SIZE = 0xFFFFFF
MAX_FILENAME_SIZE = 1024
MAX_ACTIVE_TRANSFERS = 8
MAX_PACKET_DELAY = 4.0
COVER_PAYLOAD = bytes(range(8, 64))


@dataclass(frozen=True)
class Message:
    sender_id: uuid.UUID
    message_id: uuid.UUID
    content: bytes
    filename: str | None = None


def encode_message(message: Message) -> bytes:
    """O envelope e seu CRC também são transmitidos como nibbles ocultos."""
    kind = TEXT if message.filename is None else FILE
    if kind == TEXT:
        message.content.decode("utf-8")
    name = (message.filename or "").encode("utf-8")
    if kind == FILE and not name:
        raise ValueError("O arquivo precisa ter um nome.")
    if len(name) > MAX_FILENAME_SIZE:
        raise ValueError("Nome de arquivo muito longo.")
    if FRAME_HEADER.size + len(name) + len(message.content) > MAX_FRAME_SIZE:
        raise ValueError("O conteúdo excede o limite de aproximadamente 16 MiB.")
    prefix = FRAME_PREFIX.pack(
        MAGIC, message.sender_id.bytes, message.message_id.bytes, kind, len(name)
    )
    body = name + message.content
    crc = zlib.crc32(body, zlib.crc32(prefix))
    return prefix + struct.pack("!I", crc) + body


def decode_message(frame: bytes) -> Message:
    if not FRAME_HEADER.size <= len(frame) <= MAX_FRAME_SIZE:
        raise ValueError("Tamanho de mensagem inválido.")
    magic, sender, message_id, kind, name_size, crc = FRAME_HEADER.unpack_from(frame)
    if magic != MAGIC or kind not in (TEXT, FILE):
        raise ValueError("Protocolo de mensagem inválido.")
    if name_size > MAX_FILENAME_SIZE or FRAME_HEADER.size + name_size > len(frame):
        raise ValueError("Nome de arquivo inválido.")
    body = frame[FRAME_HEADER.size:]
    expected_crc = zlib.crc32(body, zlib.crc32(frame[:FRAME_PREFIX.size]))
    if expected_crc != crc:
        raise ValueError("A mensagem falhou na verificação de integridade.")
    if (kind == TEXT and name_size != 0) or (kind == FILE and name_size == 0):
        raise ValueError("Tipo de conteúdo inválido.")
    name = body[:name_size].decode("utf-8") if kind == FILE else None
    content = body[name_size:]
    if kind == TEXT:
        content.decode("utf-8")  # Não exibir textos incompletos ou corrompidos.
    return Message(uuid.UUID(bytes=sender), uuid.UUID(bytes=message_id), content, name)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def create_icmp(stego_byte: int, identifier: int, sequence: int) -> bytes:
    payload = bytes([stego_byte]) + COVER_PAYLOAD[1:]
    header = ICMP_HEADER.pack(0, 0, 0, identifier, sequence & 0xFFFF)
    crc = checksum(header + payload)
    return ICMP_HEADER.pack(0, 0, crc, identifier, sequence & 0xFFFF) + payload


def parse_icmp(packet: bytes) -> tuple[int, int, int] | None:
    """Sockets raw IPv4 incluem o cabeçalho IP, cujo tamanho pode variar."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ip_size = (packet[0] & 0x0F) * 4
    total_size = struct.unpack_from("!H", packet, 2)[0]
    if ip_size < 20 or not ip_size + ICMP_HEADER.size <= total_size <= len(packet):
        return None
    if packet[9] != socket.IPPROTO_ICMP:
        return None
    # Fragmentos ainda não remontados não contêm uma mensagem ICMP completa.
    if struct.unpack_from("!H", packet, 6)[0] & 0x3FFF:
        return None
    icmp = packet[ip_size:total_size]
    if len(icmp) != ICMP_HEADER.size + len(COVER_PAYLOAD):
        return None
    kind, code, _, identifier, sequence = ICMP_HEADER.unpack_from(icmp)
    if kind != 0 or code != 0 or checksum(icmp) != 0:
        return None
    payload = icmp[ICMP_HEADER.size:]
    if payload[1:] != COVER_PAYLOAD[1:]:
        return None
    return identifier, sequence, payload[0]


def build_data_byte(sequence_bit: int, part: int, nibble: int) -> int:
    parity = bin(nibble).count("1") % 2
    return (sequence_bit << 6) | (part << 5) | (parity << 4) | nibble


def iter_stego_bytes(frame: bytes, is_file: bool = False):
    if not FRAME_HEADER.size <= len(frame) <= MAX_FRAME_SIZE:
        raise ValueError("Tamanho de transmissão inválido.")
    yield 0, START
    for index, shift in enumerate(range(20, -1, -4), 1):
        yield index, 0x90 | ((len(frame) >> shift) & 0x0F)
    yield 7, 0xB0 if is_file else 0xBF
    for index, value in enumerate(frame):
        yield 8 + index * 2, build_data_byte(index & 1, 0, value >> 4)
        yield 9 + index * 2, build_data_byte(index & 1, 1, value & 0x0F)
    yield 8 + len(frame) * 2, END


@dataclass
class IncomingTransfer:
    next_index: int = 1
    size: int = 0
    extension: int = 0
    high_nibble: int = 0
    data: bytearray = field(default_factory=bytearray)
    updated: float = field(default_factory=time.monotonic)
    invalid: bool = False

    def feed(self, sequence: int, value: int) -> tuple[bytes, int] | None:
        # Duplicatas não avançam o estado. Perda/reordenação exige retransmissão.
        if self.invalid or sequence != (self.next_index & 0xFFFF):
            return None
        index = self.next_index
        if index <= 6:
            if value & 0xF0 != 0x90:
                self.invalid = True
            else:
                self.size = (self.size << 4) | (value & 0x0F)
                if index == 6 and self.size < FRAME_HEADER.size:
                    self.invalid = True
        elif index == 7:
            if value not in (0xB0, 0xBF):
                self.invalid = True
            self.extension = value & 0x0F
        elif index < 8 + self.size * 2:
            offset = index - 8
            nibble = value & 0x0F
            expected = build_data_byte((offset // 2) & 1, offset & 1, nibble)
            if value != expected:
                self.invalid = True
            elif offset % 2 == 0:
                self.high_nibble = nibble
            else:
                self.data.append((self.high_nibble << 4) | nibble)
        elif index == 8 + self.size * 2 and value == END:
            if len(self.data) == self.size:
                return bytes(self.data), self.extension
            self.invalid = True
        else:
            self.invalid = True
        self.next_index += 1
        self.updated = time.monotonic()
        return None


def safe_filename(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip(" .")
    if not name:
        return "arquivo.bin"
    reserved = {"CON", "PRN", "AUX", "NUL"}
    reserved.update(f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10))
    if name.split(".", 1)[0].upper() in reserved:
        name = "_" + name
    # Nomes muito longos também podem exceder o limite do sistema de arquivos.
    if len(name.encode("utf-8")) > 180:
        suffix = Path(name).suffix[:20]
        name = name.encode("utf-8")[:140].decode("utf-8", errors="ignore") + suffix
    return name


class ChatClient:
    def __init__(
        self, sock, peer_ip: str, *, delay: float = 0.005,
        ack_timeout: float = 3.0, attempts: int = 3,
        output_dir: Path = Path("received_files"), display=print,
    ):
        self.sock = sock
        self.peer_ip = peer_ip
        self.delay = delay
        self.ack_timeout = ack_timeout
        self.attempts = attempts
        self.output_dir = Path(output_dir)
        self.display = display
        self.sender_id = uuid.uuid4()
        self.stop = threading.Event()
        self.outbox = queue.Queue(maxsize=16)
        self.incoming: dict[int, IncomingTransfer] = {}
        self.seen: OrderedDict[tuple[uuid.UUID, uuid.UUID], None] = OrderedDict()
        self.pending: dict[int, tuple[int, threading.Event]] = {}
        self.own_transfers: dict[int, float] = {}
        self.pending_lock = threading.Lock()
        self.history_lock = threading.Lock()
        self.print_lock = threading.Lock()
        self.history: list[tuple[str, str, str, str]] = []
        self.threads: list[threading.Thread] = []

    def notify(self, text: str):
        with self.print_lock:
            self.display(text)

    def start(self):
        self.sock.settimeout(0.2)
        for name, target in (("recepcao", self._receive_loop), ("envio", self._send_loop)):
            thread = threading.Thread(name=name, target=target, daemon=True)
            self.threads.append(thread)
            thread.start()

    def close(self):
        self.stop.set()
        self.sock.close()
        with self.pending_lock:
            for _, event in self.pending.values():
                event.set()
        for thread in self.threads:
            thread.join(timeout=2)

    def send(self, content: bytes, filename: str | None = None) -> uuid.UUID:
        message = Message(self.sender_id, uuid.uuid4(), content, filename)
        frame = encode_message(message)
        self.outbox.put_nowait((message, frame))
        return message.message_id

    def record(self, direction: str, content: str, status: str):
        with self.history_lock:
            self.history.append((datetime.now().strftime("%H:%M:%S"), direction, content, status))

    def show_history(self):
        with self.history_lock:
            entries = list(self.history)
        if not entries:
            self.notify("Ainda não há mensagens no histórico.")
            return
        self.notify("\n".join(
            f"[{stamp}] {direction}: {content} ({status})"
            for stamp, direction, content, status in entries
        ))

    def _expire_transfers(self):
        now = time.monotonic()
        idle_limit = max(10.0, self.delay * 4 + self.ack_timeout * 2)
        for identifier, transfer in list(self.incoming.items()):
            if now - transfer.updated > idle_limit:
                del self.incoming[identifier]
        with self.pending_lock:
            for identifier, expiry in list(self.own_transfers.items()):
                if expiry < now:
                    del self.own_transfers[identifier]

    def _receive_loop(self):
        while not self.stop.is_set():
            try:
                packet, address = self.sock.recvfrom(65535)
            except socket.timeout:
                self._expire_transfers()
                continue
            except OSError as exc:
                if not self.stop.is_set():
                    self.notify(f"Erro na recepção: {exc}. Pressione Enter para encerrar.")
                    self.stop.set()
                break
            self.handle_packet(packet, address[0])
            self._expire_transfers()

    def handle_packet(self, packet: bytes, source_ip: str):
        if source_ip != self.peer_ip:
            return
        parsed = parse_icmp(packet)
        if parsed is None:
            return
        identifier, sequence, value = parsed
        with self.pending_lock:
            if value == ACK:
                pending = self.pending.get(identifier)
                if pending and pending[0] == sequence:
                    pending[1].set()
                return
            if identifier in self.own_transfers:
                return  # No localhost, o socket também recebe nossos próprios envios.
        if sequence == 0 and value == START:
            if identifier in self.incoming:
                # START duplicado não deve apagar os nibbles já recebidos.
                return
            if len(self.incoming) >= MAX_ACTIVE_TRANSFERS:
                oldest = min(self.incoming, key=lambda key: self.incoming[key].updated)
                del self.incoming[oldest]
            self.incoming[identifier] = IncomingTransfer()
            return
        transfer = self.incoming.get(identifier)
        if transfer is None:
            return
        completed = transfer.feed(sequence, value)
        if transfer.invalid or completed is not None:
            del self.incoming[identifier]
        if completed is not None:
            self._accept_message(identifier, sequence, *completed)

    def _accept_message(self, identifier: int, sequence: int, frame: bytes, extension: int):
        try:
            message = decode_message(frame)
        except (ValueError, UnicodeError):
            return
        if message.sender_id == self.sender_id:
            return
        if (message.filename is None) != (extension == 0x0F):
            return
        key = (message.sender_id, message.message_id)
        if key not in self.seen:
            if message.filename is None:
                content = message.content.decode("utf-8")
            else:
                try:
                    path = self._save_file(message.filename, message.content)
                except OSError as exc:
                    self.notify(f"Não foi possível salvar o arquivo: {exc}")
                    return  # Só confirmar depois de salvar com sucesso.
                content = f"Arquivo recebido: {path} ({len(message.content)} bytes)"
            self.record("Outra pessoa", content, "recebida")
            self.notify(f"[{datetime.now():%H:%M:%S}] Outra pessoa: {content}")
            self.seen[key] = None
            if len(self.seen) > 1024:
                self.seen.popitem(last=False)
        try:
            self.sock.sendto(create_icmp(ACK, identifier, sequence), (self.peer_ip, 0))
        except OSError:
            pass  # Uma retransmissão receberá nova confirmação, sem repetir a mensagem.

    def _save_file(self, filename: str, content: bytes) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        name = safe_filename(filename)
        path = self.output_dir / name
        index = 1
        while True:
            try:
                destination = path.open("xb")
            except FileExistsError:
                path = self.output_dir / f"{Path(name).stem}_{index}{Path(name).suffix}"
                index += 1
                continue
            try:
                with destination:
                    destination.write(content)
            except OSError:
                path.unlink(missing_ok=True)
                raise
            return path

    def _send_loop(self):
        while not self.stop.is_set():
            try:
                message, frame = self.outbox.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                delivered = self._transmit(frame, message.filename is not None)
                if self.stop.is_set():
                    break
                content = (message.content.decode("utf-8") if message.filename is None
                           else f"Arquivo: {message.filename} ({len(message.content)} bytes)")
                status = "entrega confirmada" if delivered else "sem confirmação de entrega"
                self.record("Você", content, status)
                if delivered:
                    self.notify(f"Entrega confirmada: {content}")
                else:
                    self.notify(f"Sem confirmação após {self.attempts} tentativa(s): {content}")
            finally:
                self.outbox.task_done()

    def _transmit(self, frame: bytes, is_file: bool) -> bool:
        end_sequence = (8 + len(frame) * 2) & 0xFFFF
        for attempt in range(self.attempts):
            if self.stop.is_set():
                return False
            event = threading.Event()
            with self.pending_lock:
                identifier = secrets.randbelow(65536)
                while identifier in self.own_transfers:
                    identifier = secrets.randbelow(65536)
                lifetime = max(30.0, (9 + len(frame) * 2) * self.delay + self.ack_timeout + 5)
                self.own_transfers[identifier] = time.monotonic() + lifetime
                self.pending[identifier] = (end_sequence, event)
            try:
                for sequence, value in iter_stego_bytes(frame, is_file):
                    if self.stop.is_set():
                        return False
                    self.sock.sendto(create_icmp(value, identifier, sequence), (self.peer_ip, 0))
                    if self.delay and self.stop.wait(self.delay):
                        return False
                deadline = time.monotonic() + self.ack_timeout
                while not self.stop.is_set():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    if event.wait(min(0.1, remaining)):
                        return not self.stop.is_set()
            except OSError as exc:
                if not self.stop.is_set():
                    self.notify(f"Falha no envio: {exc}")
                    if isinstance(exc, PermissionError):
                        self.notify("O sistema bloqueou o envio ICMP. Confira os privilégios "
                                    "e as regras de firewall/rede.")
            finally:
                with self.pending_lock:
                    self.pending.pop(identifier, None)
            if attempt + 1 < self.attempts and not self.stop.is_set():
                self.notify(f"Sem confirmação; repetindo envio ({attempt + 2}/{self.attempts}).")
        return False


HELP = """Digite uma mensagem e pressione Enter para enviar.
/arquivo CAMINHO   Enviar arquivo (aceita caminhos entre aspas)
/historico         Ver mensagens enviadas e recebidas nesta execução
/ajuda             Mostrar comandos
/sair              Encerrar o chat (cancela os envios pendentes)
//texto            Enviar uma mensagem que começa com /"""


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-d", "--destino", "--destination", default="127.0.0.1",
                        help="IP ou hostname da outra pessoa (padrão: 127.0.0.1)")
    parser.add_argument("-s", "--origem", "--source", "--bind", default="0.0.0.0",
                        help="IP local para bind (padrão: 0.0.0.0)")
    parser.add_argument("--intervalo", type=float, default=0.005,
                        help="Segundos entre pacotes (padrão: 0.005)")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="Segundos para aguardar confirmação após o envio (padrão: 3)")
    parser.add_argument("--tentativas", type=int, default=3,
                        help="Número total de tentativas de entrega, de 1 a 10 (padrão: 3)")
    parser.add_argument("--pasta-recebidos", type=Path, default=Path("received_files"),
                        help="Pasta para arquivos recebidos (padrão: received_files)")
    args = parser.parse_args(argv)
    if not math.isfinite(args.intervalo) or not 0 <= args.intervalo <= MAX_PACKET_DELAY:
        parser.error("--intervalo precisa estar entre 0 e 4 segundos.")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
        parser.error("--timeout precisa ser maior que 0 e no máximo 60 segundos.")
    if not 1 <= args.tentativas <= 10:
        parser.error("--tentativas precisa estar entre 1 e 10.")
    try:
        args.destino = socket.gethostbyname(args.destino)
        args.origem = socket.gethostbyname(args.origem)
    except socket.gaierror as exc:
        parser.error(f"Não foi possível resolver o endereço: {exc}")
    return args


def main(argv=None) -> int:
    args = parse_arguments(argv)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.bind((args.origem, 0))
    except OSError as exc:
        if sock is not None:
            sock.close()
        print(f"Não foi possível abrir o socket ICMP: {exc}")
        print("Execute como administrador no Windows ou com sudo no Linux.")
        print("Confira também se o IP de origem pertence a este computador.")
        return 1

    client = ChatClient(
        sock, args.destino, delay=args.intervalo, ack_timeout=args.timeout,
        attempts=args.tentativas, output_dir=args.pasta_recebidos,
        display=lambda text: print(f"\n{text}", flush=True),
    )
    print(f"Chat esteganografado | IP local: {args.origem} | Outra pessoa: {args.destino}")
    print(HELP)
    print("A entrega será confirmada quando a outra pessoa receber a mensagem completa.")
    try:
        client.start()
        while not client.stop.is_set():
            line = input("Você> ")
            if client.stop.is_set():
                break
            if not line.strip():
                continue
            command, _, argument = line.partition(" ")
            command = command.lower()
            try:
                if command == "/sair":
                    break
                if command == "/ajuda":
                    client.notify(HELP)
                elif command == "/historico":
                    client.show_history()
                elif command == "/arquivo":
                    path_text = argument.strip()
                    if len(path_text) >= 2 and path_text[0] == path_text[-1] and path_text[0] in "\"'":
                        path_text = path_text[1:-1]
                    if not path_text:
                        raise ValueError("Use /arquivo CAMINHO.")
                    path = Path(path_text).expanduser()
                    # Ler no máximo o limite + 1 permite rejeitar arquivos grandes sem carregá-los.
                    with path.open("rb") as source:
                        content = source.read(MAX_FRAME_SIZE + 1)
                    client.send(content, path.name)
                    client.notify(f"Arquivo na fila: {path.name}")
                elif line.startswith("/") and not line.startswith("//"):
                    client.notify("Comando desconhecido. Digite /ajuda ou use // para enviar /.")
                else:
                    client.send((line[1:] if line.startswith("//") else line).encode("utf-8"))
            except queue.Full:
                client.notify("A fila está cheia. Aguarde a conclusão dos envios.")
            except (OSError, ValueError) as exc:
                client.notify(f"Não foi possível enviar: {exc}")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client.close()
    print("\nChat encerrado.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
