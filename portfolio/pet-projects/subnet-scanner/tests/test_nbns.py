"""Unit tests for the NBNS node-status query and parser."""

from __future__ import annotations

import struct

import pytest

from core.nbns import NODE_STATUS_QUERY, nbns_query, parse_nbstat_response


def _build_response(name: str, suffix: int, flags: int, mac: bytes) -> bytes:
    """Assemble a minimal but well-formed NODE STATUS RESPONSE."""

    header = struct.pack(">HHHHHH", 0x4146, 0x8400, 0, 1, 0, 0)
    # Answer name: 0x20 + 32 encoded bytes + terminator (content is skipped).
    answer_name = bytes([0x20]) + b"CK" + b"AA" * 15 + bytes([0x00])
    rr = struct.pack(">HH", 0x0021, 0x0001) + struct.pack(">I", 0) + struct.pack(">H", 0)
    num_names = bytes([1])
    entry = name.encode("ascii").ljust(15, b" ") + bytes([suffix]) + struct.pack(">H", flags)
    return header + answer_name + rr + num_names + entry + mac


def test_query_is_nbstat_wildcard():
    """The request is a NBSTAT query for the wildcard name."""

    assert NODE_STATUS_QUERY[12] == 0x20  # encoded-name length
    assert NODE_STATUS_QUERY[13:15] == b"CK"  # start of the encoded "*"
    assert NODE_STATUS_QUERY[-4:] == b"\x00\x21\x00\x01"  # QTYPE=NBSTAT, QCLASS=IN


def test_parse_extracts_name_and_mac():
    """A unique workstation entry yields its name and the trailing MAC."""

    data = _build_response("WINBOX", suffix=0x00, flags=0x0400, mac=bytes.fromhex("001122334455"))
    name, mac = parse_nbstat_response(data)
    assert name == "WINBOX"
    assert mac == "00:11:22:33:44:55"


def test_parse_skips_group_names():
    """Group (e.g. WORKGROUP) names are not taken as the computer name."""

    data = _build_response(
        "WORKGROUP", suffix=0x00, flags=0x8000, mac=bytes.fromhex("001122334455")
    )
    name, mac = parse_nbstat_response(data)
    assert name is None  # group bit set → skipped
    assert mac == "00:11:22:33:44:55"


def test_parse_too_short_returns_none():
    assert parse_nbstat_response(b"\x00" * 10) == (None, None)


def test_parse_all_zero_mac_is_dropped():
    data = _build_response("HOST", suffix=0x00, flags=0x0400, mac=b"\x00" * 6)
    name, mac = parse_nbstat_response(data)
    assert name == "HOST"
    assert mac is None


@pytest.mark.asyncio
async def test_nbns_query_handles_unreachable(monkeypatch):
    """A socket error resolves to (None, None) rather than raising."""

    import asyncio

    loop = asyncio.get_running_loop()

    async def boom(*args, **kwargs):
        raise OSError("network unreachable")

    monkeypatch.setattr(loop, "create_datagram_endpoint", boom)
    assert await nbns_query("203.0.113.1", timeout=0.1) == (None, None)
