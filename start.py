#!/usr/bin/env python3
"""PycraftCNN — a Tkinter GUI client for Minecraft (pyCraft).

Run the GUI:

    python3 start.py

Try it with no real server and no account — the "Demo server" button in
the window starts a local demo server and connects to it.

Run the headless example instead:

    python3 basicTest.py
"""

from pycraft_gui.app import main

if __name__ == "__main__":
    main()
