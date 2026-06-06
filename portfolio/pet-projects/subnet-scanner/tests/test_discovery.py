"""Unit tests for the host discovery module."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from core.discovery import discover_hosts


class _FakeWriter:
    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


def _make_open_connection(behavior: dict[tuple[str, int], str]):
    """Build a fake ``asyncio.open_connection`` driven by a behavior table.

    behavior values:
        "open"     — handshake succeeds
        "refused"  — raises ConnectionRefusedError (host still alive)
        "timeout"  — coroutine that never resolves (caught by wait_for)
    """

    async def fake_open(host: str, port: int, *args, **kwargs):
        action = behavior.get((host, port), "timeout")
        if action == "open":
            return (object(), _FakeWriter())
        if action == "refused":
            raise ConnectionRefusedError
        # timeout: hang forever so asyncio.wait_for raises TimeoutError
        await asyncio.sleep(3600)
        raise RuntimeError("unreachable")

    return fake_open


@pytest.mark.asyncio
async def test_host_alive_when_any_probe_opens():
    """A single successful probe is enough to mark the host alive."""

    behavior = {
        ("10.0.0.1", 80): "open",
        ("10.0.0.1", 443): "timeout",
        ("10.0.0.1", 22): "timeout",
        ("10.0.0.1", 445): "timeout",
    }
    with patch(
        "core.discovery.asyncio.open_connection", side_effect=_make_open_connection(behavior)
    ):
        hosts = await discover_hosts(["10.0.0.1"], timeout=0.05, use_arp=False, use_nbns=False)
    assert len(hosts) == 1
    assert hosts[0].ip == "10.0.0.1"
    assert hosts[0].alive is True
    assert hosts[0].method == "tcp"


@pytest.mark.asyncio
async def test_host_alive_when_probe_refused():
    """Connection refused means the host is up, just not serving that port."""

    behavior = {
        ("10.0.0.2", 80): "refused",
        ("10.0.0.2", 443): "timeout",
        ("10.0.0.2", 22): "timeout",
        ("10.0.0.2", 445): "timeout",
    }
    with patch(
        "core.discovery.asyncio.open_connection", side_effect=_make_open_connection(behavior)
    ):
        hosts = await discover_hosts(["10.0.0.2"], timeout=0.05, use_arp=False, use_nbns=False)
    assert len(hosts) == 1


@pytest.mark.asyncio
async def test_host_dead_when_all_probes_time_out():
    """All probes timing out is treated as the host being down."""

    behavior: dict[tuple[str, int], str] = {}  # all → timeout
    with patch(
        "core.discovery.asyncio.open_connection", side_effect=_make_open_connection(behavior)
    ):
        hosts = await discover_hosts(["10.0.0.3"], timeout=0.05, use_arp=False, use_nbns=False)
    assert hosts == []


@pytest.mark.asyncio
async def test_only_alive_hosts_returned():
    """Out of a batch, only responsive hosts appear in the output."""

    behavior = {
        ("10.0.0.1", 80): "open",
        ("10.0.0.2", 22): "refused",
        # 10.0.0.3 — nothing configured → all timeout
    }
    with patch(
        "core.discovery.asyncio.open_connection", side_effect=_make_open_connection(behavior)
    ):
        hosts = await discover_hosts(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            timeout=0.05,
            use_arp=False,
            use_nbns=False,
        )
    ips = sorted(h.ip for h in hosts)
    assert ips == ["10.0.0.1", "10.0.0.2"]


@pytest.mark.asyncio
async def test_discover_returns_empty_for_empty_targets():
    """Empty input → empty output, no crash."""

    with patch("core.discovery.asyncio.open_connection", new=AsyncMock()):
        assert await discover_hosts([]) == []


# --- firewall-aware augmentation (ARP cache + NBNS) ------------------------


@pytest.mark.asyncio
async def test_arp_cache_finds_firewalled_host():
    """A host that drops every TCP probe is still found via the ARP cache."""

    async def neighbor() -> dict[str, str]:
        return {"192.168.1.50": "aa:bb:cc:dd:ee:ff"}

    with patch(
        "core.discovery.asyncio.open_connection", side_effect=_make_open_connection({})
    ):  # every probe times out → no TCP signal
        hosts = await discover_hosts(
            ["192.168.1.50"],
            timeout=0.05,
            use_arp=True,
            use_nbns=False,
            neighbor_reader=neighbor,
        )
    assert len(hosts) == 1
    assert hosts[0].ip == "192.168.1.50"
    assert hosts[0].mac == "aa:bb:cc:dd:ee:ff"
    assert hosts[0].method == "arp"


@pytest.mark.asyncio
async def test_nbns_finds_windows_host_with_name():
    """A silent-to-TCP Windows host is found and named via NBNS."""

    async def nbns(ip: str, timeout: float) -> tuple[str | None, str | None]:
        return ("DESKTOP-ABC123", "00:11:22:33:44:55")

    with patch("core.discovery.asyncio.open_connection", side_effect=_make_open_connection({})):
        hosts = await discover_hosts(
            ["192.168.1.60"],
            timeout=0.05,
            use_arp=False,
            use_nbns=True,
            nbns_querier=nbns,
        )
    assert len(hosts) == 1
    assert hosts[0].hostname == "DESKTOP-ABC123"
    assert hosts[0].mac == "00:11:22:33:44:55"
    assert hosts[0].method == "nbns"


@pytest.mark.asyncio
async def test_signals_combine_and_arp_mac_wins():
    """All three signals agree → joined method; ARP MAC beats the NBNS MAC."""

    async def neighbor() -> dict[str, str]:
        return {"192.168.1.70": "aa:aa:aa:aa:aa:aa"}

    async def nbns(ip: str, timeout: float) -> tuple[str | None, str | None]:
        return ("WINBOX", "bb:bb:bb:bb:bb:bb")

    behavior = {("192.168.1.70", 445): "open"}
    with patch(
        "core.discovery.asyncio.open_connection",
        side_effect=_make_open_connection(behavior),
    ):
        hosts = await discover_hosts(
            ["192.168.1.70"],
            timeout=0.05,
            neighbor_reader=neighbor,
            nbns_querier=nbns,
        )
    assert hosts[0].method == "tcp+arp+nbns"
    assert hosts[0].mac == "aa:aa:aa:aa:aa:aa"  # ARP cache wins
    assert hosts[0].hostname == "WINBOX"


@pytest.mark.asyncio
async def test_arp_reader_failure_degrades_gracefully():
    """A crashing ARP reader must not sink the scan — TCP signal still stands."""

    async def boom() -> dict[str, str]:
        raise OSError("neighbour table unavailable")

    behavior = {("192.168.1.80", 80): "open"}
    with patch(
        "core.discovery.asyncio.open_connection",
        side_effect=_make_open_connection(behavior),
    ):
        hosts = await discover_hosts(
            ["192.168.1.80"],
            timeout=0.05,
            use_arp=True,
            use_nbns=False,
            neighbor_reader=boom,
        )
    assert len(hosts) == 1
    assert hosts[0].method == "tcp"
