"""Server address parsing for the GUI client.

Kept as a pure function (no Tkinter, no network) so it can be unit tested
on its own. Accepts what a player actually types — ``play.example.com``,
``localhost:25565``, ``[::1]:25565`` — and normalises it to a (host, port)
pair for ``minecraft.networking.connection.Connection``.
"""

import re

DEFAULT_PORT = 25565

_ADDRESS_RE = re.compile(
    r"((?P<host>[^\[\]:]+)|\[(?P<addr>[^\[\]]+)\])(:(?P<port>\d+))?$")


class InvalidServerAddress(ValueError):
    """Raised when the server field cannot be parsed."""


def parse_server_address(server):
    """Parse a server address string into a ``(host, port)`` tuple.

    >>> parse_server_address("localhost")
    ('localhost', 25565)
    >>> parse_server_address("play.example.com:25566")
    ('play.example.com', 25566)
    >>> parse_server_address("[::1]:25565")
    ('::1', 25565)
    """
    if server is None:
        raise InvalidServerAddress("Server address is required")
    server = server.strip()
    if not server:
        raise InvalidServerAddress("Server address is required")

    match = _ADDRESS_RE.match(server)
    if match is None:
        raise InvalidServerAddress(
            "Invalid server address %r — expected host or host:port" % server)

    host = match.group("host") or match.group("addr")
    port = match.group("port")
    if port is not None:
        port = int(port)
        if not 0 < port < 65536:
            raise InvalidServerAddress("Port %d is out of range" % port)
        return host, port
    return host, DEFAULT_PORT
