"""Testes de protocolo e de dois participantes sem privilégios de socket raw."""

from __future__ import annotations

import itertools
from pathlib import Path
import queue
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid

import chat


def ipv4(icmp: bytes, options: bytes = b"") -> bytes:
    if len(options) % 4:
        raise ValueError("Opções IPv4 precisam estar alinhadas a quatro bytes.")
    header = bytearray(20 + len(options))
    header[0] = (4 << 4) | (len(header) // 4)
    struct.pack_into("!H", header, 2, len(header) + len(icmp))
    header[8] = 64
    header[9] = socket.IPPROTO_ICMP
    header[12:16] = socket.inet_aton("127.0.0.1")
    header[16:20] = socket.inet_aton("127.0.0.1")
    header[20:] = options
    return bytes(header) + icmp


def message(content: bytes = b"ola", filename: str | None = None) -> chat.Message:
    return chat.Message(uuid.uuid4(), uuid.uuid4(), content, filename)


def feed_frame(frame: bytes, is_file: bool = False, skip: int | None = None,
               duplicate: int | None = None):
    receiver = chat.IncomingTransfer()
    result = None
    for index, value in chat.iter_stego_bytes(frame, is_file):
        if index == 0 or index == skip:
            continue
        result = receiver.feed(index & 0xFFFF, value)
        if index == duplicate:
            receiver.feed(index & 0xFFFF, value)
    return receiver, result


class CodecTests(unittest.TestCase):
    def test_utf8_round_trip_preserves_accents_and_emoji(self):
        original = message("Olá, você está aí? 🛰️".encode("utf-8"))
        self.assertEqual(chat.decode_message(chat.encode_message(original)), original)

    def test_binary_and_empty_files_round_trip(self):
        for content in (bytes(range(256)), b""):
            with self.subTest(size=len(content)):
                original = message(content, "documento com espaço.bin")
                self.assertEqual(chat.decode_message(chat.encode_message(original)), original)

    def test_crc_rejects_changed_content_and_metadata(self):
        frame = chat.encode_message(message(b"hello"))
        for offset in (10, len(frame) - 1):
            corrupt = bytearray(frame)
            corrupt[offset] ^= 0x01
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                chat.decode_message(bytes(corrupt))

    def test_short_frames_and_invalid_utf8_are_rejected(self):
        with self.assertRaises(ValueError):
            chat.decode_message(b"invalid")
        with self.assertRaises(UnicodeError):
            chat.decode_message(chat.encode_message(message(b"\xff")))

    def test_limits_and_empty_file_names_are_rejected(self):
        for original in (message(b"", ""), message(b"", "a" * 1025)):
            with self.subTest(filename_size=len(original.filename)), self.assertRaises(ValueError):
                chat.encode_message(original)
        with mock.patch.object(chat, "MAX_FRAME_SIZE", chat.FRAME_HEADER.size + 2):
            with self.assertRaises(ValueError):
                chat.encode_message(message(b"123"))


class PacketTests(unittest.TestCase):
    def test_round_trip_handles_ipv4_options_and_sequence_wrap(self):
        packet = ipv4(chat.create_icmp(0x9B, 42, 65537), b"\x01\x01\x00\x00")
        self.assertEqual(chat.parse_icmp(packet), (42, 1, 0x9B))

    def test_all_truncated_packets_are_safely_rejected(self):
        packet = ipv4(chat.create_icmp(chat.START, 42, 0))
        for size in range(len(packet)):
            with self.subTest(size=size):
                self.assertIsNone(chat.parse_icmp(packet[:size]))

    def test_bad_checksum_and_unrelated_ping_are_rejected(self):
        original = ipv4(chat.create_icmp(chat.START, 42, 0))
        corrupt = bytearray(original)
        corrupt[-1] ^= 1
        self.assertIsNone(chat.parse_icmp(bytes(corrupt)))
        icmp = bytearray(chat.create_icmp(chat.START, 42, 0))
        icmp[9] ^= 1  # Payload de outro programa, com checksum ICMP válido.
        struct.pack_into("!H", icmp, 2, 0)
        struct.pack_into("!H", icmp, 2, chat.checksum(bytes(icmp)))
        self.assertIsNone(chat.parse_icmp(ipv4(bytes(icmp))))

    def test_invalid_ip_headers_and_fragments_are_rejected(self):
        original = ipv4(chat.create_icmp(chat.START, 42, 0))
        for offset, value in ((0, 0x65), (0, 0x44), (9, 17), (6, 0x20)):
            packet = bytearray(original)
            packet[offset] = value
            with self.subTest(offset=offset, value=value):
                self.assertIsNone(chat.parse_icmp(bytes(packet)))


class TransferTests(unittest.TestCase):
    def test_nibble_stream_round_trip_ignores_duplicate_packet(self):
        frame = chat.encode_message(message("sequência".encode("utf-8")))
        transfer, result = feed_frame(frame, duplicate=12)
        self.assertFalse(transfer.invalid)
        self.assertEqual(result, (frame, 0x0F))

    def test_lost_packet_never_produces_incomplete_message(self):
        frame = chat.encode_message(message(b"never incomplete"))
        _, result = feed_frame(frame, skip=12)
        self.assertIsNone(result)

    def test_wrong_parity_invalidates_transfer(self):
        frame = chat.encode_message(message())
        transfer = chat.IncomingTransfer()
        for index, value in chat.iter_stego_bytes(frame):
            if index == 0:
                continue
            transfer.feed(index, value ^ 0x10 if index == 8 else value)
        self.assertTrue(transfer.invalid)

    def test_large_frame_survives_16_bit_sequence_wrap(self):
        frame = chat.encode_message(message(bytes(range(256)) * 130, "large.bin"))
        self.assertGreater(len(frame) * 2, 65536)
        transfer, result = feed_frame(frame, is_file=True)
        self.assertFalse(transfer.invalid)
        self.assertEqual(result, (frame, 0))


class SimulatedRawSocket:
    def __init__(self, network):
        self.network = network
        self.inbox = queue.Queue()
        self.timeout = 0.2
        self.closed = False
        network.sockets.append(self)

    def settimeout(self, timeout):
        self.timeout = timeout

    def recvfrom(self, size):
        try:
            item = self.inbox.get(timeout=self.timeout)
        except queue.Empty:
            raise socket.timeout() from None
        if item is None:
            raise OSError("Socket fechado")
        return item[:size], ("127.0.0.1", 0)

    def sendto(self, data, address):
        if self.closed:
            raise OSError("Socket fechado")
        self.network.send(self, data)
        return len(data)

    def close(self):
        self.closed = True
        self.inbox.put(None)


class SimulatedNetwork:
    """Replica raw localhost: cada socket vê inclusive seus próprios datagramas."""

    def __init__(self):
        self.sockets = []
        self.lock = threading.Lock()
        self.drop = lambda sender, data: False
        self.dropped = 0
        self.starts = 0

    def send(self, sender, data):
        with self.lock:
            _, _, _, _, sequence = chat.ICMP_HEADER.unpack_from(data)
            if data[8] == chat.START and sequence == 0:
                self.starts += 1
            if self.drop(sender, data):
                self.dropped += 1
                return
            packet = ipv4(data)
            for destination in self.sockets:
                if not destination.closed:
                    destination.inbox.put(packet)


class ChatIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.network = SimulatedNetwork()
        # Identificadores únicos tornam os testes independentes da aleatoriedade.
        numbers = itertools.count(100)
        patcher = mock.patch.object(chat.secrets, "randbelow", side_effect=lambda _: next(numbers))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.logs = [[], []]
        self.clients = [
            chat.ChatClient(SimulatedRawSocket(self.network), "127.0.0.1", delay=0,
                            ack_timeout=0.15, attempts=3,
                            output_dir=Path(self.temp.name) / str(index),
                            display=self.logs[index].append)
            for index in range(2)
        ]
        for client in self.clients:
            client.start()
            self.addCleanup(client.close)

    def wait_for(self, condition, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.005)
        self.fail(f"Tempo esgotado. Históricos: {[self.entries(c) for c in self.clients]}")

    @staticmethod
    def entries(client):
        with client.history_lock:
            return list(client.history)

    def wait_for_confirmation(self, client):
        self.wait_for(lambda: any(item[3] == "entrega confirmada" for item in self.entries(client)))

    def drop_once(self, predicate):
        def drop(sender, data):
            if self.network.dropped == 0 and predicate(sender, data):
                return True
            return False
        self.network.drop = drop

    def test_simultaneous_conversation_has_confirmed_delivery_both_ways(self):
        first, second = self.clients
        first.send("Olá da pessoa A".encode("utf-8"))
        second.send("Resposta da pessoa B 🛰️".encode("utf-8"))
        self.wait_for_confirmation(first)
        self.wait_for_confirmation(second)
        self.assertEqual(len(self.entries(first)), 2)
        self.assertEqual(len(self.entries(second)), 2)
        received = [item[2] for item in self.entries(first) if item[1] == "Outra pessoa"]
        self.assertEqual(received, ["Resposta da pessoa B 🛰️"])
        self.assertFalse(any("pessoa A" in line for line in self.logs[0]
                             if "Outra pessoa:" in line))

    def test_invalid_utf8_is_rejected_before_queueing_and_worker_survives(self):
        first, second = self.clients
        with self.assertRaises(UnicodeError):
            first.send(b"\xff")
        self.assertTrue(first.outbox.empty())
        self.assertEqual(self.network.starts, 0)
        self.assertTrue(all(thread.is_alive() for thread in first.threads))
        first.send(b"valid message after rejected input")
        self.wait_for_confirmation(first)
        self.assertEqual(self.entries(second)[0][2], "valid message after rejected input")

    def test_duplicate_start_mid_frame_preserves_already_received_nibbles(self):
        receiver = self.clients[1]
        frame = chat.encode_message(message(b"preserve progress after duplicate START"))
        identifier = 19
        for index, value in chat.iter_stego_bytes(frame):
            receiver.handle_packet(ipv4(chat.create_icmp(value, identifier, index)), "127.0.0.1")
            if index == 20:
                transfer = receiver.incoming[identifier]
                progress = bytes(transfer.data)
                self.assertTrue(progress)
                receiver.handle_packet(ipv4(chat.create_icmp(chat.START, identifier, 0)), "127.0.0.1")
                self.assertIs(receiver.incoming[identifier], transfer)
                self.assertEqual(bytes(transfer.data), progress)
                self.assertEqual(transfer.next_index, 21)
        self.assertEqual(len(self.entries(receiver)), 1)
        self.assertEqual(self.entries(receiver)[0][2], "preserve progress after duplicate START")

    def test_full_incomplete_pool_evicts_oldest_and_accepts_new_message(self):
        receiver = self.clients[1]
        for identifier in range(10, 10 + chat.MAX_ACTIVE_TRANSFERS):
            receiver.handle_packet(ipv4(chat.create_icmp(chat.START, identifier, 0)), "127.0.0.1")
        self.assertEqual(len(receiver.incoming), chat.MAX_ACTIVE_TRANSFERS)
        receiver.incoming[10].updated -= 1
        frame = chat.encode_message(message(b"delivery after incomplete pool saturation"))
        for index, value in chat.iter_stego_bytes(frame):
            receiver.handle_packet(ipv4(chat.create_icmp(value, 30, index)), "127.0.0.1")
            self.assertLessEqual(len(receiver.incoming), chat.MAX_ACTIVE_TRANSFERS)
        self.assertNotIn(10, receiver.incoming)
        self.assertEqual(len(self.entries(receiver)), 1)
        self.assertEqual(self.entries(receiver)[0][2], "delivery after incomplete pool saturation")

    def test_packet_loss_retries_and_delivers_once(self):
        first, second = self.clients
        self.drop_once(lambda sender, data: sender is first.sock
                       and struct.unpack_from("!H", data, 6)[0] == 12)
        first.send(b"recover lost nibble")
        self.wait_for_confirmation(first)
        self.assertEqual(self.network.dropped, 1)
        self.assertEqual(self.network.starts, 2)
        self.assertEqual(len(self.entries(second)), 1)

    def test_lost_ack_retries_without_duplicate_text(self):
        first, second = self.clients
        self.drop_once(lambda sender, data: data[8] == chat.ACK)
        first.send(b"do not duplicate")
        self.wait_for_confirmation(first)
        self.assertEqual(self.network.dropped, 1)
        self.assertEqual(self.network.starts, 2)
        self.assertEqual(len(self.entries(second)), 1)

    def test_lost_ack_does_not_save_file_twice_or_allow_path_traversal(self):
        first, second = self.clients
        self.drop_once(lambda sender, data: data[8] == chat.ACK)
        content = bytes(range(256))
        first.send(content, "../../escape.bin")
        self.wait_for_confirmation(first)
        paths = list(second.output_dir.iterdir())
        self.assertEqual([path.name for path in paths], ["escape.bin"])
        self.assertEqual(paths[0].read_bytes(), content)
        self.assertEqual(len(self.entries(second)), 1)

    def test_two_files_with_same_name_never_overwrite_existing_file(self):
        first, second = self.clients
        first.send(b"first", "same.txt")
        self.wait_for_confirmation(first)
        first.send(b"second", "same.txt")
        self.wait_for(lambda: len(self.entries(first)) == 2)
        self.assertEqual((second.output_dir / "same.txt").read_bytes(), b"first")
        self.assertEqual((second.output_dir / "same_1.txt").read_bytes(), b"second")

    def test_wrong_source_and_unmatched_ack_are_ignored(self):
        client = self.clients[0]
        client.handle_packet(ipv4(chat.create_icmp(chat.START, 19, 0)), "192.0.2.10")
        self.assertEqual(client.incoming, {})
        event = threading.Event()
        with client.pending_lock:
            client.pending[19] = (120, event)
        client.handle_packet(ipv4(chat.create_icmp(chat.ACK, 19, 119)), "127.0.0.1")
        self.assertFalse(event.is_set())
        client.handle_packet(ipv4(chat.create_icmp(chat.ACK, 19, 120)), "192.0.2.10")
        self.assertFalse(event.is_set())

    def test_all_lost_acks_report_uncertain_delivery_without_duplicate(self):
        first, second = self.clients
        self.network.drop = lambda sender, data: data[8] == chat.ACK
        first.send(b"may have arrived")
        self.wait_for(lambda: bool(self.entries(first)))
        self.assertEqual(self.entries(first)[0][3], "sem confirmação de entrega")
        self.assertEqual(len(self.entries(second)), 1)
        self.assertEqual(self.network.starts, 3)

    def test_shutdown_interrupts_pending_confirmation_and_stops_threads(self):
        first = self.clients[0]
        self.network.drop = lambda sender, data: True
        first.ack_timeout = 10
        first.send(b"pending")
        self.wait_for(lambda: self.network.starts >= 1)
        first.close()
        self.assertTrue(first.stop.is_set())
        self.assertTrue(all(not thread.is_alive() for thread in first.threads))

    def test_expired_incomplete_transfer_does_not_block_new_messages(self):
        client = self.clients[0]
        transfer = chat.IncomingTransfer(updated=time.monotonic() - 100)
        # Expiração usa apenas o relógio monotônico; sem esperar no teste.
        client.incoming[19] = transfer
        client._expire_transfers()
        self.assertNotIn(19, client.incoming)


if __name__ == "__main__":
    unittest.main()
