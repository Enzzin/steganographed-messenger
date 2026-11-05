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


@dataclass(frozen=True)
class ChatEvent:
    """Evento do transporte; callbacks devem encaminhá-lo sem bloquear a rede."""

    kind: str
    message_id: uuid.UUID | None = None
    content: str = ""
    filename: str | None = None
    path: str | None = None
    progress: float | None = None
    attempt: int = 1
    fatal: bool = False


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
        output_dir: Path = Path("received_files"), display=print, on_event=None,
    ):
        self.sock = sock
        self.peer_ip = peer_ip
        self.delay = delay
        self.ack_timeout = ack_timeout
        self.attempts = attempts
        self.output_dir = Path(output_dir)
        self.display = display
        self.on_event = on_event
        self.sender_id = uuid.uuid4()
        self.stop = threading.Event()
        self.outbox = queue.Queue(maxsize=16)
        self.outbox_lock = threading.Lock()
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

    def emit(self, kind: str, **details):
        if self.on_event is not None:
            try:
                self.on_event(ChatEvent(kind, **details))
            except Exception:
                # A apresentação não pode interromper o transporte nem seus ACKs.
                pass

    @staticmethod
    def message_description(message: Message) -> str:
        if message.filename is None:
            return message.content.decode("utf-8")
        return f"Arquivo: {message.filename} ({len(message.content)} bytes)"

    def _cancel_message(self, message: Message):
        self.emit("canceled", message_id=message.message_id,
                  content=self.message_description(message), filename=message.filename)

    def start(self):
        self.sock.settimeout(0.2)
        for name, target in (("recepcao", self._receive_loop), ("envio", self._send_loop)):
            thread = threading.Thread(name=name, target=target, daemon=True)
            self.threads.append(thread)
            thread.start()

    def close(self):
        self.stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        with self.pending_lock:
            for _, event in self.pending.values():
                event.set()
        with self.outbox_lock:
            while True:
                try:
                    message, _ = self.outbox.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._cancel_message(message)
                finally:
                    self.outbox.task_done()
        for thread in self.threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2)

    def send(self, content: bytes, filename: str | None = None) -> uuid.UUID:
        message = Message(self.sender_id, uuid.uuid4(), content, filename)
        frame = encode_message(message)
        with self.outbox_lock:
            if self.stop.is_set():
                raise ValueError("O chat está desconectado.")
            self.outbox.put_nowait((message, frame))
            self.emit("queued", message_id=message.message_id,
                      content=self.message_description(message), filename=message.filename)
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
                    self.emit("error", content=f"Erro na recepção: {exc}", fatal=True)
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
            path = None
            if message.filename is None:
                content = message.content.decode("utf-8")
            else:
                try:
                    path = self._save_file(message.filename, message.content)
                except OSError as exc:
                    self.notify(f"Não foi possível salvar o arquivo: {exc}")
                    self.emit("error", message_id=message.message_id,
                              content=f"Não foi possível salvar o arquivo: {exc}",
                              filename=message.filename)
                    return  # Só confirmar depois de salvar com sucesso.
                content = f"Arquivo recebido: {path} ({len(message.content)} bytes)"
            self.record("Outra pessoa", content, "recebida")
            self.notify(f"[{datetime.now():%H:%M:%S}] Outra pessoa: {content}")
            self.emit("received", message_id=message.message_id, content=content,
                      filename=message.filename, path=str(path) if path is not None else None)
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
                # send() publica queued antes de o worker poder publicar sending.
                with self.outbox_lock:
                    canceled = self.stop.is_set()
                if canceled:
                    self._cancel_message(message)
                    continue
                delivered = self._transmit(frame, message.filename is not None, message.message_id)
                if self.stop.is_set():
                    self._cancel_message(message)
                    break
                content = self.message_description(message)
                status = "entrega confirmada" if delivered else "sem confirmação de entrega"
                self.record("Você", content, status)
                self.emit("delivered" if delivered else "failed",
                          message_id=message.message_id, content=content,
                          filename=message.filename)
                if delivered:
                    self.notify(f"Entrega confirmada: {content}")
                else:
                    self.notify(f"Sem confirmação após {self.attempts} tentativa(s): {content}")
            finally:
                self.outbox.task_done()

    def _transmit(self, frame: bytes, is_file: bool, message_id: uuid.UUID | None = None) -> bool:
        end_sequence = (8 + len(frame) * 2) & 0xFFFF
        total_packets = 9 + len(frame) * 2
        for attempt in range(self.attempts):
            if self.stop.is_set():
                return False
            self.emit("sending", message_id=message_id, attempt=attempt + 1, progress=0)
            last_progress = -1
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
                    progress = (sequence + 1) * 100 // total_packets
                    if progress > last_progress:
                        self.emit("progress", message_id=message_id,
                                  progress=progress, attempt=attempt + 1)
                        last_progress = progress
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
                    explanation = f"Falha no envio: {exc}"
                    if isinstance(exc, PermissionError):
                        self.notify("O sistema bloqueou o envio ICMP. Confira os privilégios "
                                    "e as regras de firewall/rede.")
                        explanation = ("O sistema bloqueou o envio ICMP. Confira os privilégios "
                                       "e as regras de firewall/rede.")
                    self.emit("error", message_id=message_id, content=explanation,
                              attempt=attempt + 1)
            finally:
                with self.pending_lock:
                    self.pending.pop(identifier, None)
            if attempt + 1 < self.attempts and not self.stop.is_set():
                self.notify(f"Sem confirmação; repetindo envio ({attempt + 2}/{self.attempts}).")
        return False


class ChatWindow:
    """Toda operação Tk acontece na thread principal; a rede usa uma fila de eventos."""

    NAVY = "#142c46"
    MUTED = "#718298"
    TEAL = "#147d70"
    BACKGROUND = "#f4f7fb"

    def __init__(self, root, args, *, client_factory=ChatClient, socket_factory=None):
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk = tk, ttk
        self.root = root
        self.client_factory = client_factory
        self.socket_factory = socket_factory or socket.socket
        self.client = None
        self.events = queue.Queue()
        self.session = 0
        self.cancel_connect = threading.Event()
        self.lifecycle_lock = threading.Lock()
        self.closed = False
        self.scroll_id = None
        self.connecting = False
        self.loading_file = False
        self.outgoing = {}
        self.transcript = []
        self.wrap_labels = []
        self.config_widgets = []
        self.local_ip = tk.StringVar(value=args.origem)
        self.peer_ip = tk.StringVar(value=args.destino)
        self.interval = tk.StringVar(value=f"{args.intervalo * 1000:g}")
        self.timeout = tk.StringVar(value=f"{args.timeout:g}")
        self.attempts = tk.StringVar(value=str(args.tentativas))
        self.folder = tk.StringVar(value=str(args.pasta_recebidos))
        self.root.title("Stego Messenger")
        self.root.geometry("1120x780")
        self.root.minsize(920, 660)
        self.root.configure(bg=self.BACKGROUND)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("Chat.Vertical.TScrollbar", background="#c9d4df",
                        troughcolor=self.BACKGROUND, borderwidth=0, arrowsize=12)
        style.configure("Chat.Horizontal.TProgressbar", troughcolor="#cce3dd",
                        background=self.TEAL, borderwidth=0, thickness=3)
        self._build_sidebar()
        self._build_conversation()
        self._set_controls(False)
        self.poll_id = self.root.after(60, self._poll)

    def _button(self, parent, text, command, *, primary=False, dark=False, **kwargs):
        bg = "#71e2c0" if primary and dark else self.TEAL if primary else "#25415d" if dark else "#eaf0f5"
        fg = self.NAVY if primary and dark else "white" if primary or dark else "#30475f"
        return self.tk.Button(
            parent, text=text, command=command, bg=bg, fg=fg,
            activebackground="#92efd2" if dark and primary else "#dbe8ec" if not primary else "#196d63",
            activeforeground=fg, relief="flat", bd=0, cursor="hand2",
            font=("Segoe UI", 10, "bold"), padx=14, pady=10,
            disabledforeground="#8ca0b0", **kwargs,
        )

    def _build_sidebar(self):
        tk = self.tk
        sidebar = tk.Frame(self.root, bg=self.NAVY, width=284)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        logo = tk.Frame(sidebar, bg=self.NAVY)
        logo.pack(fill="x", padx=24, pady=(28, 28))
        tk.Label(logo, text="S", font=("Segoe UI", 22, "bold"), bg="#71e2c0",
                 fg=self.NAVY, width=2).pack(side="left", padx=(0, 12))
        brand = tk.Frame(logo, bg=self.NAVY)
        brand.pack(side="left")
        tk.Label(brand, text="Stego", bg=self.NAVY, fg="white",
                 font=("Segoe UI", 18, "bold")).pack(anchor="w")
        tk.Label(brand, text="MESSENGER", bg=self.NAVY, fg="#9fb4ca",
                 font=("Segoe UI", 9)).pack(anchor="w")
        body = tk.Frame(sidebar, bg=self.NAVY)
        body.pack(fill="x", padx=24)
        tk.Label(body, text="Sua conexão", bg=self.NAVY, fg="white",
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(body, text="Configure os dois lados da conversa.", bg=self.NAVY,
                 fg="#a9bed2", font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 20))
        self._field(body, "Seu IP local", self.local_ip)
        self._field(body, "IP da outra pessoa", self.peer_ip)
        tk.Label(body, text="Pasta de recebidos", bg=self.NAVY, fg="#c2d1e1",
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 6))
        folder_row = tk.Frame(body, bg=self.NAVY)
        folder_row.pack(fill="x", pady=(0, 12))
        entry = self._entry(folder_row, self.folder)
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        browse = self._button(folder_row, "…", self.choose_folder, dark=True, width=2)
        browse.pack(side="right", padx=(5, 0))
        self.config_widgets.append(browse)
        self.advanced_toggle = tk.Button(
            body, text="Opções de envio  +", command=self.toggle_advanced, relief="flat",
            bg=self.NAVY, fg="#a9bed2", activebackground=self.NAVY,
            activeforeground="white", bd=0, anchor="w", cursor="hand2",
            font=("Segoe UI", 9), pady=6,
        )
        self.advanced_toggle.pack(fill="x", pady=(0, 4))
        self.advanced = tk.Frame(body, bg=self.NAVY)
        self._field(self.advanced, "Intervalo entre pacotes (ms)", self.interval)
        advanced_row = tk.Frame(self.advanced, bg=self.NAVY)
        advanced_row.pack(fill="x")
        for title, variable, side in (("Espera (s)", self.timeout, "left"),
                                      ("Tentativas", self.attempts, "right")):
            column = tk.Frame(advanced_row, bg=self.NAVY, width=110)
            column.pack(side=side, fill="x", expand=True, padx=(0, 6) if side == "left" else (6, 0))
            self._field(column, title, variable, width=8)
        self.session_button = self._button(body, "Abrir sessão", self.toggle_connection,
                                          primary=True, dark=True)
        self.session_button.pack(fill="x", pady=(12, 0))
        bottom = tk.Frame(sidebar, bg=self.NAVY)
        bottom.pack(side="bottom", fill="x", padx=24, pady=24)
        tk.Frame(bottom, bg="#304760", height=1).pack(fill="x", pady=(0, 16))
        self.state_label = tk.Label(bottom, text="●  Sessão fechada", bg=self.NAVY,
                                    fg="#b4c6d7", anchor="w", font=("Segoe UI", 10, "bold"))
        self.state_label.pack(fill="x")
        self.state_detail = tk.Label(
            bottom, text="Cada pessoa abre a sessão com os IPs invertidos.",
            bg=self.NAVY, fg="#a9bed2", wraplength=228, justify="left",
            font=("Segoe UI", 9), anchor="w",
        )
        self.state_detail.pack(fill="x", pady=(8, 12))
        self._button(bottom, "Como conectar", self.show_help, dark=True).pack(fill="x")

    def _entry(self, parent, variable, width=18):
        entry = self.tk.Entry(parent, textvariable=variable, width=width,
                              bg="#f8fafc", fg="#172f46", insertbackground=self.NAVY,
                              disabledbackground="#d8e1eb", disabledforeground="#64748b",
                              relief="flat", bd=0, font=("Segoe UI", 10))
        self.config_widgets.append(entry)
        return entry

    def _field(self, parent, title, variable, width=18):
        self.tk.Label(parent, text=title, bg=self.NAVY, fg="#c2d1e1",
                      font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 6))
        self._entry(parent, variable, width).pack(fill="x", ipady=8, pady=(0, 14))

    def _build_conversation(self):
        tk = self.tk
        main = tk.Frame(self.root, bg=self.BACKGROUND)
        main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(main, bg="white", padx=28, pady=22)
        header.pack(fill="x")
        avatar = tk.Canvas(header, width=44, height=44, bg="white", highlightthickness=0)
        avatar.create_oval(1, 1, 43, 43, fill="#e0f4ec", outline="")
        avatar.create_text(22, 22, text="S", font=("Segoe UI", 17, "bold"), fill=self.TEAL)
        avatar.pack(side="left", padx=(0, 14))
        titles = tk.Frame(header, bg="white")
        titles.pack(side="left", fill="x", expand=True)
        tk.Label(titles, text="Conversa", font=("Segoe UI", 19, "bold"),
                 bg="white", fg=self.NAVY).pack(anchor="w")
        self.peer_label = tk.Label(titles, text="Abra uma sessão para começar", bg="white",
                                   fg=self.MUTED, font=("Segoe UI", 10))
        self.peer_label.pack(anchor="w", pady=(2, 0))
        tools = tk.Frame(main, bg="white", padx=28)
        tools.pack(fill="x")
        self._button(tools, "Pasta de recebidos", self.open_received_folder).pack(side="left", pady=(0, 14))
        self._button(tools, "Salvar conversa", self.export_conversation).pack(side="left", padx=8, pady=(0, 14))
        self.session_hint = tk.Label(tools, text="Histórico desta execução", bg="white",
                                      fg=self.MUTED, font=("Segoe UI", 9))
        self.session_hint.pack(side="right")
        tk.Frame(main, bg="#e0e7ef", height=1).pack(fill="x")
        area = tk.Frame(main, bg=self.BACKGROUND)
        area.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(area, bg=self.BACKGROUND, highlightthickness=0, bd=0)
        scrollbar = self.ttk.Scrollbar(area, orient="vertical", command=self.canvas.yview,
                                      style="Chat.Vertical.TScrollbar")
        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.messages = tk.Frame(self.canvas, bg=self.BACKGROUND, padx=24, pady=20)
        self.messages_window = self.canvas.create_window((0, 0), window=self.messages, anchor="nw")
        self.messages.bind("<Configure>", self._resize_scrollregion)
        self.canvas.bind("<Configure>", self._resize_messages)
        self.canvas.bind_all("<MouseWheel>", self._mousewheel, add="+")
        self.canvas.bind("<Button-4>", lambda event: self.canvas.yview_scroll(-3, "units"))
        self.canvas.bind("<Button-5>", lambda event: self.canvas.yview_scroll(3, "units"))
        self.empty = tk.Frame(area, bg=self.BACKGROUND)
        self.empty.place(relx=0.5, rely=0.43, anchor="center")
        symbol = tk.Canvas(self.empty, width=76, height=66, bg=self.BACKGROUND, highlightthickness=0)
        symbol.create_rectangle(7, 7, 66, 50, fill="#dceee9", outline="")
        symbol.create_polygon(15, 48, 15, 61, 30, 48, fill="#dceee9", outline="")
        for x in (25, 37, 49):
            symbol.create_oval(x - 2, 27, x + 2, 31, fill=self.TEAL, outline="")
        symbol.pack(pady=(0, 14))
        tk.Label(self.empty, text="Sua conversa começa aqui", bg=self.BACKGROUND,
                 fg=self.NAVY, font=("Segoe UI", 18, "bold")).pack()
        tk.Label(self.empty, text="Abra a sessão e envie sua primeira mensagem.\n"
                 "A outra pessoa usa os IPs invertidos.", bg=self.BACKGROUND,
                 fg=self.MUTED, justify="center", font=("Segoe UI", 11)).pack(pady=(9, 0))
        composer = tk.Frame(main, bg="white", padx=24, pady=16)
        composer.pack(fill="x")
        edit_border = tk.Frame(composer, bg="#e0e7ef", padx=1, pady=1)
        edit_border.pack(fill="x")
        self.editor = tk.Text(edit_border, height=3, wrap="word", relief="flat", bd=0,
                              bg="white", fg=self.NAVY, insertbackground=self.TEAL,
                              font=("Segoe UI", 11), padx=12, pady=10, undo=True)
        self.editor.pack(fill="x")
        self.placeholder = tk.Label(self.editor, bg="white", fg="#8b9bad",
                                     font=("Segoe UI", 11), cursor="xterm")
        self.placeholder.bind("<Button-1>", lambda event: self.editor.focus_set())
        self.editor.bind("<Return>", self._return_pressed)
        self.editor.bind("<KeyRelease>", lambda event: self._update_placeholder())
        self.editor.bind("<FocusIn>", lambda event: self._update_placeholder())
        self.editor.bind("<FocusOut>", lambda event: self._update_placeholder())
        actions = tk.Frame(composer, bg="white")
        actions.pack(fill="x", pady=(10, 0))
        self.attach_button = self._button(actions, "+  Anexar arquivo", self.attach_file)
        self.attach_button.pack(side="left")
        self.send_button = self._button(actions, "Enviar", self.send_text, primary=True, width=9)
        self.send_button.pack(side="right")
        self.compose_hint = tk.Label(actions, text="Enter envia · Shift+Enter quebra a linha",
                                      bg="white", fg=self.MUTED, font=("Segoe UI", 9))
        self.compose_hint.pack(side="left", padx=12)

    def _set_controls(self, active):
        editable = "disabled" if active or self.connecting else "normal"
        for widget in self.config_widgets:
            widget.configure(state=editable)
        self.editor.configure(state="normal" if active else "disabled")
        self.send_button.configure(state="normal" if active else "disabled")
        self.attach_button.configure(state="normal" if active and not self.loading_file else "disabled")
        self.session_button.configure(text="Cancelar abertura" if self.connecting
                                      else "Encerrar sessão" if active else "Abrir sessão")
        self._update_placeholder()

    def _update_placeholder(self):
        if not self.editor.get("1.0", "end-1c"):
            self.placeholder.configure(text="Escreva sua mensagem…" if self.client
                                       else "Abra uma sessão para conversar.")
            self.placeholder.place(x=12, y=10)
        else:
            self.placeholder.place_forget()

    def toggle_advanced(self):
        if self.advanced.winfo_manager():
            self.advanced.pack_forget()
            self.advanced_toggle.configure(text="Opções de envio  +")
        else:
            self.advanced.pack(fill="x", before=self.session_button)
            self.advanced_toggle.configure(text="Opções de envio  −")

    def choose_folder(self):
        from tkinter import filedialog
        selected = filedialog.askdirectory(parent=self.root, title="Onde salvar os arquivos recebidos?")
        if selected:
            self.folder.set(selected)

    def _settings(self):
        origin, destination = self.local_ip.get().strip(), self.peer_ip.get().strip()
        if not destination:
            raise ValueError("Informe o IP ou nome do computador da outra pessoa.")
        try:
            delay = float(self.interval.get().replace(",", ".")) / 1000
            timeout = float(self.timeout.get().replace(",", "."))
            attempts = int(self.attempts.get())
        except ValueError:
            raise ValueError("Use números válidos nas opções de envio.") from None
        if not math.isfinite(delay) or not 0 <= delay <= MAX_PACKET_DELAY:
            raise ValueError("O intervalo precisa estar entre 0 e 4000 milissegundos.")
        if not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("A espera precisa ser maior que 0 e no máximo 60 segundos.")
        if not 1 <= attempts <= 10:
            raise ValueError("Use de 1 a 10 tentativas.")
        folder = Path(self.folder.get().strip() or "received_files").expanduser()
        return origin or "0.0.0.0", destination, delay, timeout, attempts, folder

    def toggle_connection(self):
        from tkinter import messagebox
        if self.client is not None or self.connecting:
            self.disconnect()
            return
        try:
            settings = self._settings()
        except ValueError as exc:
            messagebox.showerror("Confira a configuração", str(exc), parent=self.root)
            return
        self.session += 1
        token = self.session
        self.cancel_connect = threading.Event()
        self.connecting = True
        self.state_label.configure(text="●  Abrindo sessão…", fg="#f6cf82")
        self.state_detail.configure(text="Preparando os endereços e a recepção.")
        self._set_controls(False)
        threading.Thread(target=self._open_connection,
                         args=(token, self.cancel_connect, settings), daemon=True).start()

    def _open_connection(self, token, canceled, settings):
        origin, destination, delay, timeout, attempts, folder = settings
        sock = client = None
        try:
            local = socket.gethostbyname(origin)
            peer = socket.gethostbyname(destination)
            if canceled.is_set():
                return
            sock = self.socket_factory(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.bind((local, 0))
            client = self.client_factory(
                sock, peer, delay=delay, ack_timeout=timeout, attempts=attempts,
                output_dir=folder, display=lambda text: None,
                on_event=lambda event: self.events.put((token, "chat", event)),
            )
            with self.lifecycle_lock:
                if not canceled.is_set():
                    self.events.put((token, "opened", (client, local, peer)))
                    return
        except Exception as exc:
            if not canceled.is_set():
                self.events.put((token, "open_error", exc))
        if client is not None:
            client.close()
        elif sock is not None:
            sock.close()

    def disconnect(self, *, announce=True):
        with self.lifecycle_lock:
            self.cancel_connect.set()
        self.session += 1
        client, self.client = self.client, None
        self.connecting = self.loading_file = False
        if client is not None:
            # O fechamento do socket é imediato; joins ficam fora da thread Tk.
            client.stop.set()
            try:
                client.sock.close()
            except OSError:
                pass
            threading.Thread(target=client.close, daemon=True).start()
        for bubble in self.outgoing.values():
            if bubble["state"] not in ("delivered", "failed", "canceled"):
                self._bubble_status(bubble, "canceled", "Envio cancelado", self.MUTED)
        if not self.closed:
            self._set_controls(False)
            self.state_label.configure(text="●  Sessão fechada", fg="#b4c6d7")
            self.state_detail.configure(text="Cada pessoa abre a sessão com os IPs invertidos.")
            self.peer_label.configure(text="Abra uma sessão para começar")
            self.compose_hint.configure(text="Enter envia · Shift+Enter quebra a linha")
            if announce:
                self._system_message("Sessão encerrada. Os envios pendentes foram cancelados.")

    def _poll(self):
        if self.closed:
            return
        for _ in range(150):
            try:
                token, kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if token != self.session:
                if kind == "opened":
                    threading.Thread(target=payload[0].close, daemon=True).start()
                continue
            if kind == "opened":
                self._session_opened(*payload)
            elif kind == "open_error":
                self._connection_failed(payload)
            elif kind == "chat":
                self._chat_event(payload)
            elif kind == "file_error":
                self._system_message(f"Não foi possível enviar o arquivo: {payload}")
            elif kind == "file_done":
                self.loading_file = False
                self.compose_hint.configure(text="Enter envia · Shift+Enter quebra a linha")
                self._set_controls(self.client is not None)
        if not self.closed:
            self.poll_id = self.root.after(60, self._poll)

    def _session_opened(self, client, local, peer):
        self.client = client
        self.connecting = False
        try:
            client.start()
        except Exception as exc:
            self.disconnect(announce=False)
            self._connection_failed(exc)
            return
        self._set_controls(True)
        self.peer_label.configure(text=f"Outra pessoa · {peer}")
        self.state_label.configure(text="●  Sessão aberta", fg="#71e2c0")
        self.state_detail.configure(text="A entrega será confirmada quando a outra pessoa receber.")
        self._system_message(f"Sessão aberta com {peer} · Seu IP: {local}")
        self.editor.focus_set()

    def _connection_failed(self, error):
        from tkinter import messagebox
        self.connecting = False
        self._set_controls(False)
        self.state_label.configure(text="●  Não foi possível abrir", fg="#f6cf82")
        if isinstance(error, PermissionError):
            detail = "Execute o programa como administrador no Windows ou com sudo no Linux."
        elif isinstance(error, socket.gaierror):
            detail = "Confira o IP ou nome dos computadores."
        else:
            detail = "Confira se o IP local pertence a este computador e se ICMP está permitido."
        self.state_detail.configure(text=detail)
        messagebox.showerror("Não foi possível abrir a sessão", f"{detail}\n\n{error}", parent=self.root)

    def _return_pressed(self, event):
        if event.state & 0x0001:
            return None
        self.send_text()
        return "break"

    def send_text(self):
        if self.client is None:
            return
        content = self.editor.get("1.0", "end-1c")
        if not content.strip():
            return
        try:
            self.client.send(content.encode("utf-8"))
        except (ValueError, queue.Full) as exc:
            self._system_message("A fila está cheia. Aguarde os envios." if isinstance(exc, queue.Full) else str(exc))
            return
        self.editor.delete("1.0", "end")
        self._update_placeholder()
        self.editor.focus_set()

    def attach_file(self):
        from tkinter import filedialog
        if self.client is None or self.loading_file:
            return
        selected = filedialog.askopenfilename(parent=self.root, title="Enviar um arquivo")
        if not selected or self.client is None:
            return
        self.loading_file = True
        self._set_controls(True)
        self.compose_hint.configure(text="Preparando arquivo…")
        threading.Thread(target=self._read_file,
                         args=(self.session, self.client, Path(selected)), daemon=True).start()

    def _read_file(self, token, client, path):
        try:
            with path.open("rb") as source:
                content = source.read(MAX_FRAME_SIZE + 1)
            client.send(content, path.name)
        except (OSError, ValueError, queue.Full) as exc:
            detail = "A fila está cheia. Aguarde os envios." if isinstance(exc, queue.Full) else str(exc)
            self.events.put((token, "file_error", detail))
        finally:
            self.events.put((token, "file_done", None))

    def _chat_event(self, event):
        if event.kind == "queued":
            self.outgoing[event.message_id] = self._add_bubble("Você", event.content, own=True)
        elif event.kind == "received":
            bubble = self._add_bubble("Outra pessoa", event.content, own=False)
            if event.path:
                button = self._button(bubble["frame"], "Mostrar pasta",
                                      lambda path=event.path: self._open_folder(Path(path).parent))
                button.pack(anchor="w", pady=(6, 0))
        elif event.kind in ("sending", "progress", "delivered", "failed", "canceled"):
            bubble = self.outgoing.get(event.message_id)
            if bubble is None:
                return
            if event.kind in ("sending", "progress"):
                progress = event.progress or 0
                text = f"Enviando · {progress:.0f}%"
                if event.attempt > 1:
                    text += f" · tentativa {event.attempt}"
                if progress >= 100:
                    text = "Aguardando confirmação…"
                self._bubble_status(bubble, event.kind, text, self.TEAL)
                bubble["progress"].configure(value=progress)
                bubble["progress"].pack(fill="x", pady=(6, 0))
            else:
                labels = {"delivered": ("Entregue", self.TEAL),
                          "failed": ("Sem confirmação de entrega", "#a76023"),
                          "canceled": ("Envio cancelado", self.MUTED)}
                self._bubble_status(bubble, event.kind, *labels[event.kind])
        elif event.kind == "error":
            self._system_message(event.content)
            if event.fatal:
                self.disconnect(announce=False)
                self.state_label.configure(text="●  Sessão interrompida", fg="#f6cf82")

    def _add_bubble(self, author, content, *, own):
        tk = self.tk
        self.empty.place_forget()
        should_scroll = self.canvas.yview()[1] >= 0.97 or own
        row = tk.Frame(self.messages, bg=self.BACKGROUND)
        row.pack(fill="x", pady=(0, 14))
        frame = tk.Frame(row, bg="#dff2eb" if own else "white", padx=16, pady=12,
                         highlightbackground="#cfe6dd" if own else "#e0e7ef", highlightthickness=1)
        frame.pack(side="right" if own else "left", padx=(50, 0) if own else (0, 50))
        background = frame.cget("bg")
        timestamp = datetime.now().strftime("%H:%M")
        tk.Label(frame, text=f"{author}  ·  {timestamp}", bg=background,
                 fg="#4e7568" if own else self.MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 5))
        body = tk.Label(frame, text=content, bg=background, fg=self.NAVY, justify="left",
                        wraplength=self._wrap_length(), font=("Segoe UI", 11), anchor="w")
        body.pack(anchor="w")
        self.wrap_labels.append(body)
        menu = tk.Menu(frame, tearoff=False)
        menu.add_command(label="Copiar mensagem", command=lambda: self._copy_message(content))
        body.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))
        status = tk.Label(frame, text="Na fila" if own else "Recebida", bg=background,
                          fg=self.MUTED, font=("Segoe UI", 8))
        status.pack(anchor="e", pady=(7, 0))
        progress = self.ttk.Progressbar(frame, maximum=100, style="Chat.Horizontal.TProgressbar")
        entry = {"time": timestamp, "author": author, "content": content,
                 "status": "Na fila" if own else "Recebida"}
        self.transcript.append(entry)
        bubble = {"frame": frame, "status": status, "progress": progress,
                  "state": "queued" if own else "received", "entry": entry}
        if should_scroll:
            self._schedule_scroll()
        return bubble

    def _bubble_status(self, bubble, state, text, color):
        bubble["state"] = state
        bubble["status"].configure(text=text, fg=color)
        bubble["entry"]["status"] = text
        if state in ("delivered", "failed", "canceled"):
            bubble["progress"].pack_forget()

    def _system_message(self, text):
        self.empty.place_forget()
        label = self.tk.Label(self.messages, text=text, bg=self.BACKGROUND,
                               fg=self.MUTED, wraplength=self._wrap_length(), justify="center",
                               font=("Segoe UI", 9), pady=8)
        label.pack(pady=(0, 12))
        self.wrap_labels.append(label)
        self.transcript.append({"time": datetime.now().strftime("%H:%M"),
                                "author": "Sistema", "content": text, "status": ""})
        self._schedule_scroll()

    def _copy_message(self, content):
        self.root.clipboard_clear()
        self.root.clipboard_append(content)

    def _wrap_length(self):
        return max(220, min(540, self.canvas.winfo_width() - 140))

    def _resize_messages(self, event):
        self.canvas.itemconfigure(self.messages_window, width=event.width)
        for label in self.wrap_labels:
            label.configure(wraplength=self._wrap_length())

    def _resize_scrollregion(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _schedule_scroll(self):
        if not self.closed and self.scroll_id is None:
            self.scroll_id = self.root.after_idle(self._scroll_bottom)

    def _scroll_bottom(self):
        self.scroll_id = None
        if not self.closed:
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            self.canvas.yview_moveto(1.0)

    def _mousewheel(self, event):
        # A rolagem global só atua quando o ponteiro está sobre a conversa.
        widget = event.widget
        if str(widget).startswith(str(self.messages)) or widget == self.canvas:
            self.canvas.yview_scroll(-int(event.delta / 120) or (-1 if event.delta > 0 else 1), "units")

    def open_received_folder(self):
        folder = self.client.output_dir if self.client else Path(self.folder.get() or "received_files").expanduser()
        self._open_folder(folder)

    def _open_folder(self, folder):
        import os
        import subprocess
        import sys
        from tkinter import messagebox
        try:
            folder.mkdir(parents=True, exist_ok=True)
            if sys.platform == "win32":
                os.startfile(str(folder.resolve()))
            else:
                subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(folder.resolve())])
        except OSError as exc:
            messagebox.showerror("Não foi possível abrir a pasta", str(exc), parent=self.root)

    def export_conversation(self):
        from tkinter import filedialog, messagebox
        if not self.transcript:
            messagebox.showinfo("Salvar conversa", "Ainda não há mensagens para salvar.", parent=self.root)
            return
        selected = filedialog.asksaveasfilename(
            parent=self.root, title="Salvar conversa", defaultextension=".txt",
            initialfile=f"conversa_{datetime.now():%Y%m%d_%H%M}.txt",
            filetypes=[("Arquivo de texto", "*.txt")],
        )
        if selected:
            try:
                lines = [f"[{entry['time']}] {entry['author']}: {entry['content']}"
                         + (f" ({entry['status']})" if entry["status"] else "") for entry in self.transcript]
                Path(selected).write_text("\n\n".join(lines) + "\n", encoding="utf-8")
            except OSError as exc:
                messagebox.showerror("Não foi possível salvar a conversa", str(exc), parent=self.root)

    def show_help(self):
        from tkinter import messagebox
        messagebox.showinfo(
            "Como conectar duas pessoas",
            "1. Abra o programa nos dois computadores.\n"
            "2. Informe seu IP local e o IP da outra pessoa.\n"
            "3. Na outra máquina, inverta os endereços.\n"
            "4. Clique em Abrir sessão nos dois lados.\n\n"
            "A sessão aberta permite enviar e receber. A entrega só é confirmada "
            "quando a outra pessoa recebe a mensagem completa.\n\n"
            "O programa usa ICMP. Execute como administrador no Windows ou com sudo "
            "no Linux e use uma rede que permita esse tráfego.\n\n"
            "Para testar na mesma máquina, use 127.0.0.1 nos dois campos, em duas janelas.",
            parent=self.root,
        )

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.disconnect(announce=False)
        self.root.after_cancel(self.poll_id)
        if self.scroll_id is not None:
            self.root.after_cancel(self.scroll_id)
            self.scroll_id = None
        # Resultados já publicados antes do cancelamento ainda possuem sockets.
        while True:
            try:
                _, kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "opened":
                threading.Thread(target=payload[0].close, daemon=True).start()
        self.root.destroy()


def launch_gui(args) -> int:
    try:
        import tkinter as tk
    except ImportError:
        print("Tkinter não está disponível. Instale o Python com Tcl/Tk ou use --terminal.")
        return 1
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"Não foi possível abrir a interface gráfica: {exc}")
        print("Em um ambiente sem tela, execute com --terminal.")
        return 1
    ChatWindow(root, args)
    root.mainloop()
    return 0


HELP = """Digite uma mensagem e pressione Enter para enviar.
/arquivo CAMINHO   Enviar arquivo (aceita caminhos entre aspas)
/historico         Ver mensagens enviadas e recebidas nesta execução
/ajuda             Mostrar comandos
/sair              Encerrar o chat (cancela os envios pendentes)
//texto            Enviar uma mensagem que começa com /"""


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terminal", action="store_true",
                        help="Usar o chat no terminal em vez da interface gráfica")
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
    if not args.terminal:
        return launch_gui(args)
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
