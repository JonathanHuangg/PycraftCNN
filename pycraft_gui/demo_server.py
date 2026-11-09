"""A demo Minecraft server for trying the GUI without a real server.

Built on the fake server from ``tests/fake_server.py`` — the same harness
the test suite uses, so the demo exercises the exact code path the tests
cover. On login it welcomes the player in chat, echoes anything they type
back as ``<name> message`` (the fake server's default behaviour), and sends
a PlayerPositionAndLook packet every second so the position readout moves.

Run directly::

    python3 -m pycraft_gui.demo_server

or let the GUI start it with the "Demo server" button.
"""

import json
import math
import threading
import time

from minecraft.networking.packets import clientbound

from tests.fake_server import FakeClientHandler, FakeServer


def chat_packet(text):
    """Build a ChatMessagePacket the right way: Packet.__init__ takes
    field values as keyword arguments — passing the JSON string
    positionally would set it as the packet's `context` and leave
    `json_data` unset (a latent bug in the fake server's echo, fixed
    there too). `position` 0 is a normal chat message; `sender` is
    required by the packet layout on protocol 718+ and must be a string —
    the UUID type re-parses it with uuid.UUID(value)."""
    return clientbound.play.ChatMessagePacket(
        json_data=json.dumps({"text": text}), position=0,
        sender="00000000-0000-0000-0000-000000000000")


class DemoClientHandler(FakeClientHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Created here, not in handle_play_start: the login flow already
        # writes packets (LoginSuccess) before play starts, and every write
        # goes through self.write_packet below.
        self._write_lock = threading.Lock()

    def handle_play_start(self):
        super().handle_play_start()
        self.write_packet(chat_packet(
            "Welcome to the PycraftCNN demo server! "
            "Type something in chat and it will echo back."))
        self._ticker = threading.Thread(target=self._send_positions, daemon=True)
        self._ticker.start()

    def write_packet(self, packet):
        with self._write_lock:
            super().write_packet(packet)

    def _send_positions(self):
        # Walk the player in a slow circle so the position readout moves.
        # Stops silently when the client disconnects (write fails).
        try:
            for step in range(360):
                time.sleep(1)
                angle = step * 0.1
                packet = clientbound.play.PlayerPositionAndLookPacket()
                packet.x = 100.5 + 10 * math.cos(angle)
                packet.y = 64.0
                packet.z = 200.5 + 10 * math.sin(angle)
                packet.yaw = 0.0
                packet.pitch = 0.0
                packet.flags = 0
                packet.teleport_id = step
                packet.dismount_vehicle = False
                self.write_packet(packet)
        except Exception:
            pass


def start_demo_server():
    """Start the demo server on localhost. Returns (server, port)."""
    server = FakeServer(client_handler_type=DemoClientHandler)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    return server, server.listen_socket.getsockname()[1]


if __name__ == "__main__":
    server, port = start_demo_server()
    print("Demo server listening on localhost:%d (Ctrl-C to stop)" % port)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
