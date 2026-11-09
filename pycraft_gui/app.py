"""The PycraftCNN GUI client: a Tkinter front end for pyCraft.

What it does:
- Connect to a Minecraft server (online Mojang auth, or offline mode) and
  play chat: incoming chat renders as plain text, outgoing chat sends on
  Enter.
- Show the live player position from PlayerPositionAndLook packets, and
  the connection state, in the status bar.
- "Demo server" starts a local demo server (see demo_server.py) and
  connects to it, so the client can be tried with no real server and no
  account.

The UI owns no networking. ``MinecraftController`` (controller.py) owns
the connection and posts events to a queue; this class drains the queue
with ``after()`` and updates widgets from the UI thread only.

Run with ``python3 start.py``.
"""

import time
import tkinter as tk
from tkinter import scrolledtext, ttk

from .controller import (
    ChatMessage, Connected, Disconnected, Error, MinecraftController, Position,
)
from .demo_server import start_demo_server

_POSITION_UPDATE_INTERVAL_S = 0.25  # servers send positions at up to 20 Hz


class MinecraftClientApp(tk.Tk):
    def __init__(self, controller=None):
        super().__init__()
        self.title("PycraftCNN — Minecraft Client")
        self.geometry("640x520")
        self.controller = controller or MinecraftController()
        self._demo_server = None
        self._state = "disconnected"  # disconnected | connecting | connected
        self._last_position_update = 0.0

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.server_var = tk.StringVar(value="localhost")
        self.offline_var = tk.BooleanVar(value=True)

        self._build_widgets()
        self._set_state("disconnected")
        self.after(100, self._drain_events)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- widgets -----------------------------------------------------------

    def _build_widgets(self):
        pad = {"padx": 8, "pady": 4}

        header = ttk.Frame(self)
        header.pack(fill=tk.X, **pad)
        ttk.Label(header, text="PycraftCNN", font=("", 14, "bold")).pack(side=tk.LEFT)
        self.status_label = ttk.Label(header, text="Disconnected")
        self.status_label.pack(side=tk.RIGHT)

        form = ttk.Frame(self)
        form.pack(fill=tk.X, **pad)
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Username:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(form, textvariable=self.username_var).grid(
            row=0, column=1, sticky=tk.EW)
        ttk.Label(form, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(form, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=1, column=1, sticky=tk.EW)
        ttk.Label(form, text="Server:").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(form, textvariable=self.server_var).grid(row=2, column=1, sticky=tk.EW)
        ttk.Checkbutton(form, text="Offline mode (no Mojang login)",
                        variable=self.offline_var,
                        command=self._on_offline_toggle).grid(
            row=3, column=1, sticky=tk.W)

        buttons = ttk.Frame(self)
        buttons.pack(fill=tk.X, **pad)
        self.connect_button = ttk.Button(buttons, text="Connect",
                                         command=self._on_connect)
        self.connect_button.pack(side=tk.LEFT, padx=(0, 4))
        self.disconnect_button = ttk.Button(buttons, text="Disconnect",
                                            command=self._on_disconnect)
        self.disconnect_button.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(buttons, text="Demo server",
                   command=self._on_demo).pack(side=tk.LEFT)
        self.position_label = ttk.Label(buttons, text="Position: —")
        self.position_label.pack(side=tk.RIGHT)

        self.chat_log = scrolledtext.ScrolledText(self, height=16, state=tk.DISABLED)
        self.chat_log.pack(fill=tk.BOTH, expand=True, **pad)

        chat_row = ttk.Frame(self)
        chat_row.pack(fill=tk.X, **pad)
        self.chat_input = ttk.Entry(chat_row)
        self.chat_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self.chat_input.bind("<Return>", self._on_send_chat)
        self.send_button = ttk.Button(chat_row, text="Send",
                                      command=self._on_send_chat)
        self.send_button.pack(side=tk.RIGHT)

        self._on_offline_toggle()

    # -- actions -----------------------------------------------------------

    def _on_offline_toggle(self):
        # No password exists in offline mode; grey the field out so nobody
        # types one in by habit.
        state = tk.DISABLED if self.offline_var.get() else tk.NORMAL
        self.password_entry.config(state=state)
        if self.offline_var.get():
            self.password_var.set("")

    def _on_connect(self):
        try:
            self.controller.connect(
                username=self.username_var.get(),
                password=self.password_var.get(),
                server=self.server_var.get(),
                offline=self.offline_var.get(),
            )
        except ValueError as exc:
            self._log("Error: %s" % exc)
            return
        self._set_state("connecting")
        self._log("Connecting to %s..." % self.server_var.get())

    def _on_disconnect(self):
        self.controller.disconnect()
        self._set_state("disconnected")
        self._log("Disconnected")

    def _on_demo(self):
        if self._demo_server is None:
            _server, port = start_demo_server()
            self._demo_server = port
            self._log("Demo server started on localhost:%d" % port)
        self.server_var.set("localhost:%d" % self._demo_server)
        self.username_var.set("DemoPlayer")
        self.offline_var.set(True)
        self._on_offline_toggle()
        self._on_connect()

    def _on_send_chat(self, _event=None):
        message = self.chat_input.get().strip()
        if not message:
            return
        self.controller.send_chat(message)
        self.chat_input.delete(0, tk.END)

    def _on_close(self):
        self.controller.disconnect()
        self.destroy()

    # -- events from the controller ----------------------------------------

    def _drain_events(self):
        while True:
            try:
                event = self.controller.events.get_nowait()
            except Exception:
                break
            if isinstance(event, Connected):
                self._set_state("connected")
                self._log("Connected to the game")
            elif isinstance(event, ChatMessage):
                self._log(event.text)
            elif isinstance(event, Position):
                now = time.monotonic()
                if now - self._last_position_update >= _POSITION_UPDATE_INTERVAL_S:
                    self._last_position_update = now
                    self.position_label.config(
                        text="Position: %.1f, %.1f, %.1f" % (event.x, event.y, event.z))
            elif isinstance(event, Disconnected):
                self._set_state("disconnected")
                self._log("Disconnected: %s" % event.reason)
            elif isinstance(event, Error):
                self._set_state("disconnected")
                self._log("Error: %s" % event.message)
        self.after(100, self._drain_events)

    # -- helpers -----------------------------------------------------------

    def _set_state(self, state):
        self._state = state
        if state == "connected":
            self.status_label.config(text="● Connected", foreground="green")
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.NORMAL)
            self.send_button.config(state=tk.NORMAL)
            self.chat_input.config(state=tk.NORMAL)
        elif state == "connecting":
            self.status_label.config(text="● Connecting…", foreground="orange")
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.NORMAL)
            self.send_button.config(state=tk.DISABLED)
            self.chat_input.config(state=tk.DISABLED)
        else:
            self.status_label.config(text="● Disconnected", foreground="grey")
            self.connect_button.config(state=tk.NORMAL)
            self.disconnect_button.config(state=tk.DISABLED)
            self.send_button.config(state=tk.DISABLED)
            self.chat_input.config(state=tk.DISABLED)
            self.position_label.config(text="Position: —")

    def _log(self, message):
        self.chat_log.config(state=tk.NORMAL)
        self.chat_log.insert(tk.END, message + "\n")
        self.chat_log.see(tk.END)
        self.chat_log.config(state=tk.DISABLED)


def main():
    app = MinecraftClientApp()
    app.mainloop()


if __name__ == "__main__":
    main()
