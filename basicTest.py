"""Headless example: connect to a server on localhost:25565 and send a chat
message — the same flow the GUI performs, without the window.

The original version sent the chat message immediately after
``connection.connect()``, before login had finished, so the message was
never delivered. This version waits for JoinGame (up to 10 seconds) and
then sends, and exits non-zero if the server never lets us in.

    python3 basicTest.py [username]
"""

import sys
import threading

from minecraft.networking.connection import Connection
from minecraft.networking.packets import clientbound, serverbound

JOIN_TIMEOUT_S = 10


def main(username="your_username", address="localhost", port=25565):
    # sys.argv hands us strings; the handshake packet packs the port as
    # an unsigned short, so coerce here rather than failing mid-connect.
    port = int(port)
    joined = threading.Event()

    def handle_join_game(_packet):
        print("Joined the game.")
        joined.set()

    def handle_position(packet):
        print("Received position: %s" % (packet.position,))

    connection = Connection(address, port, username=username)
    connection.register_packet_listener(
        handle_join_game, clientbound.play.JoinGamePacket)
    connection.register_packet_listener(
        handle_position, clientbound.play.PlayerPositionAndLookPacket)
    connection.connect()

    if not joined.wait(JOIN_TIMEOUT_S):
        print("Timed out waiting to join the game.", file=sys.stderr)
        connection.disconnect()
        return 1

    packet = serverbound.play.ChatPacket()
    packet.message = "Hello, Minecraft World!"
    connection.write_packet(packet)
    print("Sent chat message.")
    connection.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
