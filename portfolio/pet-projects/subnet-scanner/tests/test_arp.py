"""Unit tests for the ARP / neighbour-cache reader."""

from __future__ import annotations

import pytest

from core.arp import (
    _is_unicast,
    _normalize_mac,
    parse_neighbor_table,
    read_neighbor_table,
)

_WINDOWS_ARP_A = """
Interface: 192.168.1.5 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.50          aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
"""

_LINUX_IP_NEIGH = """
192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.50 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
192.168.1.99 dev eth0  FAILED
192.168.1.77 dev eth0  INCOMPLETE
fe80::1 dev eth0 lladdr 00:11:22:33:44:66 router REACHABLE
"""

_MACOS_ARP_AN = """
? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
? (192.168.1.50) at a:b:c:d:e:f on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""


def test_parse_windows_arp_a():
    """Windows dash-MAC rows parse; broadcast/multicast are dropped."""

    table = parse_neighbor_table(_WINDOWS_ARP_A)
    assert table == {
        "192.168.1.1": "00:11:22:33:44:55",
        "192.168.1.50": "aa:bb:cc:dd:ee:ff",
    }


def test_parse_linux_ip_neigh():
    """`ip neigh`: resolved rows kept; FAILED/INCOMPLETE and IPv6 dropped."""

    table = parse_neighbor_table(_LINUX_IP_NEIGH)
    assert table == {
        "192.168.1.1": "00:11:22:33:44:55",
        "192.168.1.50": "aa:bb:cc:dd:ee:ff",
    }


def test_parse_macos_arp_an_zero_pads_short_octets():
    """macOS prints short hex octets — they are zero-padded on normalize."""

    table = parse_neighbor_table(_MACOS_ARP_AN)
    assert table["192.168.1.1"] == "00:11:22:33:44:55"
    assert table["192.168.1.50"] == "0a:0b:0c:0d:0e:0f"
    assert "192.168.1.255" not in table  # broadcast filtered


def test_parse_empty_input():
    assert parse_neighbor_table("") == {}


def test_normalize_mac_forms():
    assert _normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert _normalize_mac("A:B:C:D:E:F") == "0a:0b:0c:0d:0e:0f"


def test_is_unicast_filters_broadcast_and_multicast():
    assert _is_unicast("00:11:22:33:44:55") is True
    assert _is_unicast("ff:ff:ff:ff:ff:ff") is False
    assert _is_unicast("00:00:00:00:00:00") is False
    assert _is_unicast("01:00:5e:00:00:16") is False  # IPv4 multicast
    assert _is_unicast("33:33:00:00:00:01") is False  # IPv6 multicast


@pytest.mark.asyncio
async def test_read_neighbor_table_uses_injected_runner():
    """The reader parses whatever the injected command runner returns."""

    async def runner(argv: list[str]) -> str:
        return "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n"

    table = await read_neighbor_table(runner=runner)
    assert table == {"192.168.1.1": "00:11:22:33:44:55"}


@pytest.mark.asyncio
async def test_read_neighbor_table_missing_command_returns_empty():
    """A missing neighbour-table binary degrades to an empty mapping."""

    async def runner(argv: list[str]) -> str:
        raise FileNotFoundError("command not found")

    assert await read_neighbor_table(runner=runner) == {}


@pytest.mark.asyncio
async def test_read_neighbor_table_oserror_returns_empty():
    """Any OSError from the runner is swallowed into an empty mapping."""

    async def runner(argv: list[str]) -> str:
        raise OSError("permission denied")

    assert await read_neighbor_table(runner=runner) == {}
