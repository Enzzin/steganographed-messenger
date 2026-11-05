"""Interface Tk real, com transporte substituído e sem janelas visíveis."""

from __future__ import annotations

from pathlib import Path
import queue
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

import chat

try:
    import tkinter as tk
except ImportError:
    tk = None


class FakeSocket:
    def __init__(self, *args):
        self.closed = False
        self.bound = None

    def bind(self, address):
        self.bound = address

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, sock, peer, **settings):
        self.sock = sock
        self.peer = peer
        self.output_dir = settings.get("output_dir", Path("received_files"))
        self.on_event = settings.get("on_event", lambda event: None)
        self.stop = threading.Event()
        self.sent = []
        self.started = False
        self.closed = False
        self.full = False

    def start(self):
        self.started = True

    def send(self, content, filename=None):
        if self.full:
            raise queue.Full
        if self.stop.is_set():
            raise ValueError("O chat está desconectado.")
        message_id = uuid.uuid4()
        self.sent.append((message_id, content, filename))
        description = content.decode("utf-8") if filename is None else f"Arquivo: {filename}"
        self.on_event(chat.ChatEvent("queued", message_id=message_id,
                                     content=description, filename=filename))
        return message_id

    def close(self):
        self.stop.set()
        self.sock.close()
        self.closed = True


@unittest.skipIf(tk is None, "Tkinter não está disponível")
class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            probe = tk.Tk()
            probe.withdraw()
            probe.destroy()
        except tk.TclError as exc:
            raise unittest.SkipTest(f"Ambiente sem tela Tk: {exc}") from exc

    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.callback_errors = []
        self.root.report_callback_exception = lambda *error: self.callback_errors.append(error)
        args = SimpleNamespace(origem="127.0.0.1", destino="127.0.0.1", intervalo=0.005,
                               timeout=3, tentativas=3, pasta_recebidos=Path("received_files"))
        self.window = chat.ChatWindow(self.root, args, client_factory=FakeClient,
                                      socket_factory=FakeSocket)
        self.dialog = mock.patch("tkinter.messagebox.showerror").start()
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.window.close()
        self.assertEqual(self.callback_errors, [])

    def wait_for(self, condition, timeout=2):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.root.update()
            if condition():
                return
            time.sleep(0.005)
        self.fail("A interface não atingiu o estado esperado.")

    def connect(self):
        self.window.toggle_connection()
        self.wait_for(lambda: self.window.client is not None)
        return self.window.client

    def test_initial_window_is_disconnected_and_close_is_idempotent(self):
        self.assertEqual(self.window.editor.cget("state"), "disabled")
        self.assertEqual(self.window.send_button.cget("state"), "disabled")
        self.assertEqual(self.window.session_button.cget("text"), "Abrir sessão")
        self.assertEqual(self.window.interval.get(), "5")
        self.window._system_message("Rolagem ainda pendente")
        self.window.close()
        self.window.close()
        self.assertTrue(self.window.closed)
        self.assertEqual(self.root.tk.call("after", "info"), "")

    def test_invalid_configuration_is_rejected_without_starting_network(self):
        cases = (("peer_ip", ""), ("interval", "nan"), ("interval", "4001"),
                 ("interval", "-1"), ("timeout", "inf"), ("timeout", "0"),
                 ("attempts", "11"), ("attempts", "1.5"))
        for name, value in cases:
            variable = getattr(self.window, name)
            original = variable.get()
            with self.subTest(field=name, value=value), self.assertRaises(ValueError):
                variable.set(value)
                self.window._settings()
            variable.set(original)
        self.window.interval.set("2,5")
        self.assertEqual(self.window._settings()[2], 0.0025)
        self.assertIsNone(self.window.client)

    def test_connection_enables_composer_and_disconnect_cancels_pending_bubbles(self):
        client = self.connect()
        self.assertTrue(client.started)
        self.assertEqual(client.sock.bound, ("127.0.0.1", 0))
        self.assertEqual(self.window.editor.cget("state"), "normal")
        self.assertTrue(all(widget.cget("state") == "disabled" for widget in self.window.config_widgets))
        self.window.editor.insert("1.0", "pendente")
        self.window.send_text()
        message_id = client.sent[0][0]
        self.wait_for(lambda: message_id in self.window.outgoing)
        self.window.disconnect()
        self.wait_for(lambda: client.closed)
        self.assertIsNone(self.window.client)
        self.assertEqual(self.window.outgoing[message_id]["state"], "canceled")
        self.assertTrue(client.sock.closed)
        self.assertEqual(self.window.editor.cget("state"), "disabled")

    def test_multiline_message_updates_queue_progress_and_delivery(self):
        client = self.connect()
        text = "Olá, você está aí?\nSegunda linha."
        self.window.editor.insert("1.0", text)
        self.window.send_text()
        message_id, content, filename = client.sent[0]
        self.assertEqual(content, text.encode("utf-8"))
        self.assertIsNone(filename)
        self.assertEqual(self.window.editor.get("1.0", "end-1c"), "")
        self.wait_for(lambda: message_id in self.window.outgoing)
        bubble = self.window.outgoing[message_id]
        self.assertEqual(bubble["status"].cget("text"), "Na fila")
        self.window._chat_event(chat.ChatEvent("progress", message_id=message_id,
                                                progress=42, attempt=2))
        self.assertIn("42%", bubble["status"].cget("text"))
        self.assertIn("tentativa 2", bubble["status"].cget("text"))
        self.window._chat_event(chat.ChatEvent("delivered", message_id=message_id))
        self.assertEqual(bubble["status"].cget("text"), "Entregue")
        self.assertEqual(bubble["entry"]["status"], "Entregue")
        self.assertEqual(bubble["progress"].winfo_manager(), "")

    def test_full_queue_keeps_draft_and_shift_enter_does_not_send(self):
        client = self.connect()
        self.window.editor.insert("1.0", "rascunho com acento: olá")
        self.assertIsNone(self.window._return_pressed(SimpleNamespace(state=1)))
        self.assertEqual(client.sent, [])
        client.full = True
        self.assertEqual(self.window._return_pressed(SimpleNamespace(state=0)), "break")
        self.assertEqual(self.window.editor.get("1.0", "end-1c"), "rascunho com acento: olá")
        self.assertIn("fila está cheia", self.window.transcript[-1]["content"])

    def test_received_file_can_open_its_containing_folder(self):
        path = str(Path(tempfile.gettempdir()) / "gui-tests" / "arquivo.pdf")
        self.window._chat_event(chat.ChatEvent("received", message_id=uuid.uuid4(),
                                                content="Arquivo recebido: arquivo.pdf", filename="arquivo.pdf", path=path))
        rows = self.window.messages.winfo_children()
        bubble = rows[-1].winfo_children()[0]
        buttons = [widget for widget in bubble.winfo_children() if isinstance(widget, tk.Button)]
        self.assertEqual(len(buttons), 1)
        with mock.patch.object(self.window, "_open_folder") as open_folder:
            buttons[0].invoke()
            open_folder.assert_called_once_with(Path(path).parent)
        self.assertEqual(self.window.transcript[-1]["status"], "Recebida")

    def test_permission_error_opens_actionable_dialog_and_allows_retry(self):
        self.window.socket_factory = mock.Mock(side_effect=PermissionError("raw bloqueado"))
        self.window.toggle_connection()
        self.wait_for(lambda: self.dialog.called)
        self.assertFalse(self.window.connecting)
        self.assertIsNone(self.window.client)
        self.assertEqual(self.window.session_button.cget("text"), "Abrir sessão")
        self.assertIn("administrador", self.dialog.call_args.args[1])
        self.assertTrue(all(widget.cget("state") == "normal" for widget in self.window.config_widgets))

    def test_stale_opened_result_closes_socket_instead_of_reconnecting(self):
        stale_token = self.window.session
        stale_client = FakeClient(FakeSocket(), "127.0.0.1")
        self.window.disconnect(announce=False)
        self.window.events.put((stale_token, "opened", (stale_client, "127.0.0.1", "127.0.0.1")))
        self.wait_for(lambda: stale_client.closed)
        self.assertIsNone(self.window.client)
        self.assertTrue(stale_client.sock.closed)

    def test_background_events_are_rendered_by_main_thread_and_fatal_error_disconnects(self):
        client = self.connect()
        worker = threading.Thread(target=lambda: client.on_event(
            chat.ChatEvent("received", message_id=uuid.uuid4(), content="recebida em paralelo")))
        worker.start()
        worker.join()
        self.wait_for(lambda: any(entry["content"] == "recebida em paralelo" for entry in self.window.transcript))
        client.on_event(chat.ChatEvent("error", content="Socket interrompido", fatal=True))
        self.wait_for(lambda: self.window.client is None)
        self.wait_for(lambda: client.closed)
        self.assertIn("interrompida", self.window.state_label.cget("text"))
        self.assertEqual(self.window.editor.cget("state"), "disabled")

    def test_file_attachment_reads_binary_data_in_background(self):
        client = self.connect()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "arquivo com espaço.bin"
            path.write_bytes(bytes(range(256)))
            with mock.patch("tkinter.filedialog.askopenfilename", return_value=str(path)):
                self.window.attach_file()
            self.wait_for(lambda: bool(client.sent) and not self.window.loading_file)
            self.assertEqual(client.sent[0][1:], (bytes(range(256)), path.name))
            self.assertEqual(self.window.attach_button.cget("state"), "normal")

    def test_export_preserves_unicode_multiline_and_current_status(self):
        self.window._chat_event(chat.ChatEvent("queued", message_id=uuid.UUID(int=1),
                                                content="Olá\nDuas linhas"))
        self.window._chat_event(chat.ChatEvent("delivered", message_id=uuid.UUID(int=1)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "conversa.txt"
            with mock.patch("tkinter.filedialog.asksaveasfilename", return_value=str(path)):
                self.window.export_conversation()
            text = path.read_text(encoding="utf-8")
            self.assertIn("Olá\nDuas linhas", text)
            self.assertIn("Entregue", text)


class EntryPointTests(unittest.TestCase):
    def test_default_launches_gui_without_opening_raw_socket(self):
        with mock.patch.object(chat, "launch_gui", return_value=0) as launch:
            with mock.patch.object(chat.socket, "socket") as raw:
                self.assertEqual(chat.main([]), 0)
                launch.assert_called_once()
                raw.assert_not_called()
                self.assertFalse(launch.call_args.args[0].terminal)


if __name__ == "__main__":
    unittest.main()
