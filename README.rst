PycraftCNN
==========

A fork of `pyCraft <https://github.com/ammaraskar/pyCraft>`_ (Ammar Askar's
Python Minecraft client library) with a Tkinter GUI client added on top.

Despite the repo name, **there is no convolutional neural network or other
machine-learning code in this repo**. The name does not match the contents;
what the fork actually adds is the GUI client below.

What this fork adds (on top of upstream pyCraft)
-------------------------------------------------

- ``pycraft_gui/`` — the GUI client, split so each part can be tested
  without a window:
  - ``app.py`` — the Tkinter window: connection form, live status and
    player position, a chat log that renders Minecraft chat JSON as
    plain text, and a chat box. Send with Enter.
  - ``controller.py`` — the connection itself. It posts events
    (connected, chat, position, disconnected, error) to a queue the UI
    drains, so the network thread never touches a widget.
  - ``chat.py`` — renders chat JSON (``text`` / ``extra`` /
    ``translate`` components, section colour codes) into the line a
    player would see in-game. The old client logged the raw JSON.
  - ``address.py`` — parses ``host``, ``host:port`` and ``[ipv6]:port``,
    default port 25565.
  - ``demo_server.py`` — a local demo server (built on the fake server
    in ``tests/``) that welcomes the player, echoes chat, and walks
    them in a circle so the position readout moves. The "Demo server"
    button in the window starts it and connects to it: the whole
    client works with no real server and no account.
- ``start.py`` — thin entry point: ``python3 start.py``.
- ``basicTest.py`` — the minimal headless example. It now waits for
  JoinGame before sending chat (the old version sent immediately after
  ``connect()``, before login had finished, so the message never
  arrived) and does nothing on import.
- ``tests/test_gui_*.py`` — tests for the address parser, the chat
  renderer, the controller against the demo server (connect, welcome,
  position tick, chat round-trip, server kick), and the Tk window
  itself under Xvfb.

Everything else — the ``minecraft`` package (protocol, authentication,
packet encoding/decoding) — is upstream pyCraft, supporting Minecraft
1.8 through 1.18.1.

Two bugs fixed in the upstream test harness (``tests/fake_server.py``),
found because the demo server exercises paths no test reached before:

- Chat packets were constructed with the JSON string as a positional
  argument, which ``Packet.__init__`` takes as the packet's ``context``,
  leaving ``json_data`` unset — writing the packet raised
  ``AttributeError``. The chat echo never worked.
- The echo also read ``self.username``; the attribute is ``user_name``.

The test suite itself is fixed for Python 3.12: the 14 failures were
all removed ``unittest`` aliases (``assertEquals``,
``assertRaisesRegexp``), and ``test_version.py`` imported
``distutils``, removed in 3.12. No test logic changed.

Requirements
------------

- Python 3 and Tkinter (standard library), plus ``cryptography``,
  ``requests`` and ``pynbt``:

.. code:: sh

    pip install -r requirements.txt

How to run
----------

GUI client:

.. code:: sh

    python3 start.py

Enter a username, password and server (``host`` or ``host:port``,
default port 25565), then Connect. For a local server that does not
need authentication, tick Offline Mode instead of logging in. Or press
"Demo server": it starts a local demo server and connects to it, so
you can try chat and the position readout with nothing else running.

Headless example:

.. code:: sh

    python3 basicTest.py [username]

This needs a Minecraft server running on ``localhost:25565``; it
connects, waits to join, and sends a chat message.

Demo server on its own:

.. code:: sh

    python3 -m pycraft_gui.demo_server

It prints the localhost port it picked; connect to it in offline mode.

Auth note: online mode uses Mojang's Yggdrasil auth, which Mojang
deprecated in favour of Microsoft accounts. It still works for
accounts that have not migrated; offline mode skips auth entirely.

Tests
-----

.. code:: sh

    python3 -m pytest tests/ -q

On Python 3.12 (Ubuntu 24.04, venv from ``requirements.txt`` plus
pytest): **130 passed, 5 skipped** under ``xvfb-run`` (129 passed, 6
skipped without a display, because the GUI window test skips).

Before this change the suite was 85 passed, 14 failed, 5 skipped, and
``test_version.py`` could not even be collected.

Attribution
-----------

Upstream pyCraft is by Ammar Askar and Jeppe Klitgaard; see
`pyCraft <https://github.com/ammaraskar/pyCraft>`_ and its
`documentation <https://pycraft.readthedocs.io/en/latest/>`_. This
fork's own changes are the GUI client, the demo server, and the test
fixes described above.
