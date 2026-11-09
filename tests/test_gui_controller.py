"""End-to-end tests for the GUI controller against the demo server.

No window, no real Minecraft server: the demo server is the fake server
from tests/fake_server.py with a welcome message and position ticks, and
the controller is the same object the Tk app drives.
"""

import queue
import time

import pytest

from pycraft_gui.controller import (
    ChatMessage, Connected, Disconnected, MinecraftController, Position,
)
from pycraft_gui.demo_server import start_demo_server


def _drain_until(controller, predicate, timeout=10):
    """Pull events until one matches, or fail after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    seen = []
    while time.monotonic() < deadline:
        try:
            event = controller.events.get(timeout=0.2)
        except queue.Empty:
            continue
        seen.append(event)
        if predicate(event):
            return event, seen
    pytest.fail("timed out waiting for event; saw: %r" % (seen,))


@pytest.fixture(scope="module")
def demo_port():
    _server, port = start_demo_server()
    return port


def test_connect_chat_and_position(demo_port):
    controller = MinecraftController()
    controller.connect("Tester", "", "localhost:%d" % demo_port, offline=True)

    _event, _seen = _drain_until(
        controller, lambda e: isinstance(e, Connected))

    # The demo server welcomes the player in chat on join.
    _event, _seen = _drain_until(
        controller, lambda e: isinstance(e, ChatMessage)
        and "Welcome" in e.text)

    # And sends a position tick every second.
    event, _seen = _drain_until(
        controller, lambda e: isinstance(e, Position), timeout=5)
    assert event.y == 64.0

    # Chat round-trips: the server echoes "<Tester> hello".
    controller.send_chat("hello")
    _event, _seen = _drain_until(
        controller, lambda e: isinstance(e, ChatMessage)
        and e.text == "<Tester> hello")

    controller.disconnect()


def test_bad_server_address_is_rejected_synchronously():
    controller = MinecraftController()
    with pytest.raises(ValueError):
        controller.connect("Tester", "", "not a : address :", offline=True)


def test_missing_username_is_rejected_synchronously():
    controller = MinecraftController()
    with pytest.raises(ValueError):
        controller.connect("", "", "localhost", offline=True)


def test_unreachable_server_reports_an_error_event():
    controller = MinecraftController()
    # Port 1 on localhost refuses connections.
    controller.connect("Tester", "", "localhost:1", offline=True)
    event, _seen = _drain_until(
        controller, lambda e: e.__class__.__name__ == "Error", timeout=10)
    assert "localhost:1" in event.message


def test_server_kick_arrives_as_disconnected_event(demo_port):
    # A server-side disconnect packet must surface as an event, not a
    # silent socket close — the UI shows the reason to the player.
    from tests.fake_server import FakeClientHandler, FakeServer
    import threading

    class KickingHandler(FakeClientHandler):
        def handle_play_start(self):
            super().handle_play_start()
            from tests.fake_server import FakeServerDisconnect
            raise FakeServerDisconnect("You are banned")

    server = FakeServer(client_handler_type=KickingHandler)
    threading.Thread(target=server.run, daemon=True).start()
    port = server.listen_socket.getsockname()[1]

    controller = MinecraftController()
    controller.connect("Tester", "", "localhost:%d" % port, offline=True)
    event, _seen = _drain_until(
        controller, lambda e: isinstance(e, Disconnected), timeout=10)
    assert "banned" in event.reason
