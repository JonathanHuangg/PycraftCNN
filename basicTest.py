from minecraft.networking.connection import Connection
from minecraft.networking.packets import clientbound, serverbound

# Assuming you have already established a connection
connection = Connection(
    address="localhost",  # Minecraft server address
    port=25565,           # Minecraft server port
    username="your_username",
)

# Example of sending a chat message
def send_chat_message(message):
    packet = serverbound.play.ChatPacket()
    packet.message = message
    connection.write_packet(packet)

# Example of handling incoming packets (e.g., player position)
def handle_packet(packet):
    if isinstance(packet, clientbound.play.PlayerPositionAndLookPacket):
        print(f"Received position: {packet.position}")

connection.register_packet_listener(handle_packet)

# Start interacting
send_chat_message("Hello, Minecraft World!")
