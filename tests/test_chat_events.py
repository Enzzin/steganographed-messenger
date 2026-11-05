"""Eventos usados pela GUI, verificados com dois participantes simulados."""

from __future__ import annotations

from pathlib import Path
import queue
import tempfile
import time
import unittest
from unittest import mock
import itertools

import chat
from test_chat import SimulatedNetwork, SimulatedRawSocket


class ChatEventTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.network = SimulatedNetwork()
        numbers = itertools.count(100)
        patcher = mock.patch.object(chat.secrets, "randbelow", side_effect=lambda _: next(numbers))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.events = [queue.Queue(), queue.Queue()]
        self.clients = [
            chat.ChatClient(
                SimulatedRawSocket(self.network), "127.0.0.1", delay=0,
                ack_timeout=0.12, attempts=2,
                output_dir=Path(self.temp.name) / str(index),
                display=lambda _: None, on_event=self.events[index].put,
            )
            for index in range(2)
        ]
        for client in self.clients:
            client.start()
            self.addCleanup(client.close)

    def events_for(self, index):
        with self.events[index].mutex:
            return list(self.events[index].queue)

    def wait_for(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.005)
        self.fail(f"Eventos não chegaram: {[self.events_for(i) for i in range(2)]}")

    def test_queued_precedes_progress_and_confirmation_for_same_message(self):
        message_id = self.clients[0].send("Olá pela GUI".encode("utf-8"))
        self.wait_for(lambda: any(e.kind == "delivered" for e in self.events_for(0)))
        events = [e for e in self.events_for(0) if e.message_id == message_id]
        kinds = [e.kind for e in events]
        self.assertEqual(kinds[0], "queued")
        self.assertEqual(kinds[1], "sending")
        self.assertEqual(kinds[-1], "delivered")
        progress = [e.progress for e in events if e.kind == "progress"]
        self.assertEqual(progress[-1], 100)
        self.assertEqual(progress, sorted(set(progress)))
        self.assertLessEqual(len(progress), 101)
        received = [e for e in self.events_for(1) if e.kind == "received"]
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].message_id, message_id)
        self.assertEqual(received[0].content, "Olá pela GUI")

    def test_lost_ack_updates_attempt_without_duplicate_received_file(self):
        def drop_ack_once(sender, packet):
            return packet[8] == chat.ACK and self.network.dropped == 0

        self.network.drop = drop_ack_once
        content = b"\x00\xff\x10"
        message_id = self.clients[0].send(content, "../../documento.bin")
        self.wait_for(lambda: any(e.kind == "delivered" for e in self.events_for(0)))
        attempts = [e.attempt for e in self.events_for(0) if e.kind == "sending"]
        self.assertEqual(attempts, [1, 2])
        received = [e for e in self.events_for(1) if e.kind == "received"]
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].message_id, message_id)
        self.assertEqual(received[0].filename, "../../documento.bin")
        self.assertEqual(Path(received[0].path).read_bytes(), content)
        self.assertEqual(Path(received[0].path).parent, self.clients[1].output_dir)

    def test_closing_cancels_active_and_queued_messages_once(self):
        self.network.drop = lambda sender, packet: True
        first = self.clients[0]
        first.ack_timeout = 10
        identifiers = {first.send(b"active"), first.send(b"queued")}
        self.wait_for(lambda: any(e.kind == "sending" for e in self.events_for(0)))
        started = time.monotonic()
        first.close()
        self.assertLess(time.monotonic() - started, 1)
        canceled = [e.message_id for e in self.events_for(0) if e.kind == "canceled"]
        self.assertEqual(set(canceled), identifiers)
        self.assertEqual(len(canceled), 2)
        self.assertEqual(first.outbox.unfinished_tasks, 0)
        self.assertFalse(any(e.kind in ("delivered", "failed") for e in self.events_for(0)))
        with self.assertRaises(ValueError):
            first.send(b"after close")

    def test_full_queue_emits_no_extra_queued_event_and_close_drains_it(self):
        events = []
        client = chat.ChatClient(SimulatedRawSocket(self.network), "127.0.0.1",
                                 on_event=events.append, display=lambda _: None)
        self.addCleanup(client.close)
        for _ in range(client.outbox.maxsize):
            client.send(b"waiting")
        with self.assertRaises(queue.Full):
            client.send(b"rejected")
        self.assertEqual(len(events), client.outbox.maxsize)
        self.assertTrue(all(e.kind == "queued" for e in events))
        client.close()
        self.assertEqual(client.outbox.unfinished_tasks, 0)
        self.assertEqual(sum(e.kind == "canceled" for e in events), client.outbox.maxsize)

    def test_faulty_presentation_callback_does_not_interrupt_delivery(self):
        def broken_callback(event):
            raise RuntimeError("Interface indisponível")

        self.clients[0].on_event = broken_callback
        self.clients[0].send(b"still delivered")
        self.wait_for(lambda: bool(self.clients[0].history))
        self.assertEqual(self.clients[0].history[0][3], "entrega confirmada")
        self.assertTrue(all(thread.is_alive() for thread in self.clients[0].threads))

    def test_socket_receive_failure_produces_fatal_event(self):
        self.clients[0].sock.inbox.put(None)
        self.wait_for(lambda: any(e.kind == "error" and e.fatal for e in self.events_for(0)))
        self.assertTrue(self.clients[0].stop.is_set())

    def test_send_permission_error_is_reported_before_failed_message(self):
        first = self.clients[0]
        with mock.patch.object(first.sock, "sendto", side_effect=PermissionError("bloqueado")):
            message_id = first.send(b"not sent")
            self.wait_for(lambda: any(e.kind == "failed" for e in self.events_for(0)))
        errors = [e for e in self.events_for(0) if e.kind == "error"]
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(e.message_id == message_id and not e.fatal for e in errors))
        self.assertIn("bloqueou o envio ICMP", errors[0].content)
        self.assertEqual(self.events_for(0)[-1].kind, "failed")


if __name__ == "__main__":
    unittest.main()
