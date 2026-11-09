import pytest

from pycraft_gui.address import InvalidServerAddress, parse_server_address


def test_bare_host_defaults_to_25565():
    assert parse_server_address("localhost") == ("localhost", 25565)


def test_host_and_port():
    assert parse_server_address("play.example.com:25566") == ("play.example.com", 25566)


def test_ipv6_with_port():
    assert parse_server_address("[::1]:25565") == ("::1", 25565)


def test_ipv6_without_port():
    assert parse_server_address("[2001:db8::1]") == ("2001:db8::1", 25565)


def test_whitespace_is_ignored():
    assert parse_server_address("  localhost:25565  ") == ("localhost", 25565)


@pytest.mark.parametrize("bad", ["", "   ", None, "localhost:", "localhost:0",
                                 "localhost:65536", "localhost:abc", "a:b:c",
                                 "[::1", "localhost:25565:1"])
def test_invalid_addresses_raise(bad):
    with pytest.raises(InvalidServerAddress):
        parse_server_address(bad)
