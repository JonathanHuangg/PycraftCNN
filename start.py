import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import re
import sys
from optparse import OptionParser
import getpass
from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import Packet, clientbound, serverbound
from minecraft.networking.packets.clientbound.play import PlayerPositionAndLookPacket

class MinecraftClientApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Minecraft Client")
        self.geometry("500x400")
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.server_var = tk.StringVar()
        self.offline_var = tk.BooleanVar()
        self.connection = None

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Username:").pack(pady=5)
        tk.Entry(self, textvariable=self.username_var).pack(pady=5)

        tk.Label(self, text="Password:").pack(pady=5)
        tk.Entry(self, textvariable=self.password_var, show="*").pack(pady=5)

        tk.Label(self, text="Server:").pack(pady=5)
        tk.Entry(self, textvariable=self.server_var).pack(pady=5)

        tk.Checkbutton(self, text="Offline Mode", variable=self.offline_var).pack(pady=5)

        tk.Button(self, text="Connect", command=self.connect).pack(pady=10)

        self.chat_log = scrolledtext.ScrolledText(self, height=10)
        self.chat_log.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)

        self.chat_input = tk.Entry(self)
        self.chat_input.pack(pady=5, padx=5, fill=tk.X)
        self.chat_input.bind("<Return>", self.send_chat)

        tk.Button(self, text="Send", command=self.send_chat).pack(pady=5)

        self.disconnect_button = tk.Button(self, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_button.pack(pady=5)

    def connect(self):
        username = self.username_var.get()
        password = self.password_var.get()
        server = self.server_var.get()
        offline = self.offline_var.get()

        if not username:
            messagebox.showerror("Error", "Username is required")
            return

        if not server:
            messagebox.showerror("Error", "Server is required")
            return

        match = re.match(r"((?P<host>[^\[\]:]+)|\[(?P<addr>[^\[\]]+)\])"
                        r"(:(?P<port>\d+))?$", server)
        
        if match is None:
            messagebox.showerror("Error", "Invalid server address")
            return

        address = match.group("host") or match.group("addr")
        port = int(match.group("port") or 25565)
        
        threading.Thread(target=self._connect_thread, args=(address, port, username, password, offline), daemon=True).start()

    def _connect_thread(self, address, port, username, password, offline):
        try:
            if offline:
                self.connect_offline(address, port, username)
            else:
                self.connect_online(address, port, username, password)
        except YggdrasilError as e:
            self.after(0, lambda e=e: messagebox.showerror("Login Failed", str(e)))
        except Exception as e:
            self.after(0, lambda e=e: messagebox.showerror("Connection Error", str(e)))

    def connect_offline(self, address, port, username):
        self.log("Connecting in offline mode...")
        connection = Connection(address, port, username=username)
        self.setup_connection(connection)
    
    def connect_online(self, address, port, username, password):
        auth_token = authentication.AuthenticationToken()
        auth_token.authenticate(username, password)
        self.log(f"Logged in as {auth_token.username}...")
        connection = Connection(address, port, auth_token=auth_token)
        self.setup_connection(connection)

    def setup_connection(self, connection):
        self.connection = connection

        def handle_join_game(join_game_packet):
            self.after(0, lambda: self.log("Connected to the game"))
            self.after(0, lambda: self.disconnect_button.config(state=tk.NORMAL))

        connection.register_packet_listener(handle_join_game, clientbound.play.JoinGamePacket)

        def handle_player_position_and_look(packet):
            x, y, z = packet.x, packet.y, packet.z
            self.after(0, lambda: self.log(f"Current Position: X={x}, Y={y}, Z={z}"))
        
        connection.register_packet_listener(handle_player_position_and_look, PlayerPositionAndLookPacket)

        def print_chat(chat_packet):
            message = f"Message ({chat_packet.field_string('position')}): {chat_packet.json_data}"

            self.after(0, lambda: self.log(message))

        connection.register_packet_listener(print_chat, clientbound.play.ChatMessagePacket)

        connection.connect()

    def disconnect(self):
        if self.connection:
            self.connection.disconnect()
            self.connection = None
            self.log("Disconnected from server")
            self.disconnect_button.config(state=tk.DISABLED)

    def send_chat(self, event=None):
        message = self.chat_input.get()
        if message and self.connection:
            packet = serverbound.play.ChatPacket()
            packet.message = message
            self.connection.write_packet(packet)
            self.chat_input.delete(0, tk.END)

    def log(self, message):
        self.chat_log.insert(tk.END, message + "\n")
        self.chat_log.see(tk.END)

def main():
    app = MinecraftClientApp()
    app.mainloop()

if __name__ == "__main__":
    main()
