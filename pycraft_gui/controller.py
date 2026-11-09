"""Connection controller: the network half of the GUI client.

The old ``start.py`` mixed Tkinter widgets, threading, and packet handling
in one class, which meant none of it could be tested without a window and
a server. This module owns the connection only. It talks to the UI through
a thread-safe queue of events — the Tk app drains the queue with
``after()`` — so the controller can be exercised headlessly against the
fake server in ``tests/``.

Events (all dataclasses, all cheap to construct on the network thread):

- ``Connected`` — the server accepted the login (JoinGame received).
- ``ChatMessage`` — a chat line, already rendered to plain text.
- ``Position`` — the player's current x/y/z (PlayerPositionAndLook).
- ``Disconnected`` — the connection ended, with a human-readable reason.
- ``Error`` — login or connection failed before play started.

Auth note: online mode uses Mojang's Yggdrasil auth (``AuthenticationToken``),
which Mojang deprecated in favour of Microsoft accounts; it still works
for accounts that have not migrated, and offline mode skips auth entirely.
The controller does not store the password past the login call.
"""

import queue
import threading
from dataclasses import dataclass

from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import clientbound, serverbound
from minecraft.networking.packets.clientbound.play import PlayerPositionAndLookPacket

from .address import InvalidServerAddress, parse_server_address
from .chat import render_chat_json


@dataclass(frozen=True)
class Connected:
    pass


@dataclass(frozen=True)
class ChatMessage:
    text: str


@dataclass(frozen=True)
class Position:
    x: float
    y: float
    z: float


@dataclass(frozen=True)
class Disconnected:
    reason: str


@dataclass(frozen=True)
class Error:
    message: str


class MinecraftController:
    """One connection to one server. Create per connect; do not reuse."""

    def __init__(self):
        self.events = queue.Queue()
        self._connection = None
        self._connect_thread = None
        self.connected = False

    # -- public API (called from the UI thread) ---------------------------

    def connect(self, username, password, server, offline):
        """Start connecting in a background thread. Returns immediately.

        Raises ``InvalidServerAddress`` or ``ValueError`` synchronously for
        bad input, so the UI can flag the field before anything networked
        happens; anything that fails later arrives as an ``Error`` event.
        """
        if not username or not username.strip():
            raise ValueError("Username is required")
        if not offline and not password:
            raise ValueError("Password is required unless offline mode is on")
        host, port = parse_server_address(server)
        username = username.strip()

        self._connect_thread = threading.Thread(
            target=self._connect_in_thread,
            args=(host, port, username, password, offline),
            daemon=True,
        )
        self._connect_thread.start()

    def send_chat(self, message):
        """Send a chat message. No-op when not connected."""
        if self._connection is None or not message:
            return
        packet = serverbound.play.ChatPacket()
        packet.message = message
        try:
            self._connection.write_packet(packet)
        except Exception:
            # The socket is gone; the disconnect path reports it.
            pass

    def disconnect(self):
        """End the connection, if there is one."""
        connection, self._connection = self._connection, None
        self.connected = False
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass

    # -- internals (run on the connect / network threads) -----------------

    def _connect_in_thread(self, host, port, username, password, offline):
        try:
            if offline:
                connection = Connection(host, port, username=username)
            else:
                token = authentication.AuthenticationToken()
                token.authenticate(username, password)
                connection = Connection(host, port, auth_token=token)
        except YggdrasilError as exc:
            self.events.put(Error("Login failed: %s" % exc))
            return
        except InvalidServerAddress as exc:
            self.events.put(Error(str(exc)))
            return
        except Exception as exc:
            self.events.put(Error("Could not connect to %s:%d: %s" % (host, port, exc)))
            return

        self._connection = connection
        self._register_listeners(connection)
        try:
            connection.connect()
        except Exception as exc:
            self.events.put(Error("Could not connect to %s:%d: %s" % (host, port, exc)))

    def _register_listeners(self, connection):
        def on_join_game(_packet):
            self.connected = True
            self.events.put(Connected())

        def on_position(packet):
            self.events.put(Position(packet.x, packet.y, packet.z))

        def on_chat(packet):
            self.events.put(ChatMessage(render_chat_json(packet.json_data)))

        def on_disconnect(packet):
            reason = render_chat_json(packet.json_data) or "Disconnected by the server"
            self.connected = False
            self.events.put(Disconnected(reason))

        connection.register_packet_listener(on_join_game, clientbound.play.JoinGamePacket)
        connection.register_packet_listener(on_position, PlayerPositionAndLookPacket)
        connection.register_packet_listener(on_chat, clientbound.play.ChatMessagePacket)
        connection.register_packet_listener(
            on_disconnect, clientbound.play.DisconnectPacket)
        connection.register_packet_listener(
            on_disconnect, clientbound.login.DisconnectPacket)
