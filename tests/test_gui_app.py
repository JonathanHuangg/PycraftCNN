"""Smoke test for the Tk window itself, under a virtual display.

Run with ``xvfb-run`` (no real display needed)::

    xvfb-run -a python3 -m pytest tests/test_gui_app.py -q

Covers the flow a player actually does: open the window, hit "Demo
server", wait for the welcome message and a position readout, send a
chat line, see the echo.
"""

import os
import time

import pytest

# This test opens a real Tk window, so it needs a display. Under CI or a
# headless shell, run it with `xvfb-run -a pytest tests/test_gui_app.py`.
if not os.environ.get("DISPLAY"):
    pytest.skip("no display available; run under xvfb-run",
                allow_module_level=True)

tk = pytest.importorskip("tkinter")

from pycraft_gui.app import MinecraftClientApp  # noqa: E402


def _pump_until(app, predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.update()
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _log_text(app):
    return app.chat_log.get("1.0", "end")


def test_demo_flow_end_to_end():
    app = MinecraftClientApp()
    try:
        assert app.status_label.cget("text") == "● Disconnected"
        assert str(app.send_button.cget("state")) == "disabled"

        app._on_demo()

        assert _pump_until(
            app, lambda: "Connected to the game" in _log_text(app)), \
            "never connected; log was:\n%s" % _log_text(app)
        assert _pump_until(
            app, lambda: "Welcome to the PycraftCNN demo server" in _log_text(app))
        assert _pump_until(
            app, lambda: app.position_label.cget("text").startswith("Position: 1"),
            timeout=5), "position never updated: %s" % app.position_label.cget("text")
        assert app.status_label.cget("text") == "● Connected"

        app.chat_input.insert(0, "hello from the gui")
        app._on_send_chat()
        assert _pump_until(
            app, lambda: "<DemoPlayer> hello from the gui" in _log_text(app)), \
            "echo never arrived; log was:\n%s" % _log_text(app)

        app._on_disconnect()
        assert app.status_label.cget("text") == "● Disconnected"
    finally:
        app.destroy()
