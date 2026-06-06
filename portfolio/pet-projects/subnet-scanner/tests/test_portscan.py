"""Unit tests for the port scanner."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from core.models import Host
from core.portscan import scan_ports


class _FakeWriter:
    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


@pytest.mark.asyncio
async def test_only_open_ports_returned():
    """Only ports where open_connection succeeds appear in the output."""

    open_ports = {81, 8080}

    async def fake_open(host: str, port: int, *args, **kwargs):
        if port in open_ports:
            return (object(), _FakeWriter())
        raise ConnectionRefusedError

    host = Host(ip="127.0.0.1", alive=True, discovered_at=datetime.now(timezone.utc))
    sem = asyncio.Semaphore(50)
    with patch("core.portscan.asyncio.open_connection", side_effect=fake_open):
        result = await scan_ports(host, [22, 80, 81, 443, 8080], sem, timeout=0.1)
    assert sorted(p.port for p in result) == [81, 8080]
    assert all(p.protocol == "tcp" for p in result)


@pytest.mark.asyncio
async def test_timeout_means_closed():
    """Connections that hang past the timeout are treated as closed."""

    async def hang_forever(host: str, port: int, *args, **kwargs):
        await asyncio.sleep(3600)
        raise RuntimeError("unreachable")

    host = Host(ip="10.0.0.10", alive=True, discovered_at=datetime.now(timezone.utc))
    sem = asyncio.Semaphore(10)
    with patch("core.portscan.asyncio.open_connection", side_effect=hang_forever):
        result = await scan_ports(host, [1234, 5678], sem, timeout=0.05)
    assert result == []


@pytest.mark.asyncio
async def test_semaphore_bounds_concurrency():
    """The semaphore must cap the number of simultaneously in-flight connections."""

    inflight = 0
    peak = 0
    lock = asyncio.Lock()

    async def slow_open(host: str, port: int, *args, **kwargs):
        nonlocal inflight, peak
        async with lock:
            inflight += 1
            peak = max(peak, inflight)
        try:
            await asyncio.sleep(0.05)
            return (object(), _FakeWriter())
        finally:
            async with lock:
                inflight -= 1

    host = Host(ip="127.0.0.1", alive=True, discovered_at=datetime.now(timezone.utc))
    cap = 5
    sem = asyncio.Semaphore(cap)
    ports = list(range(50000, 50050))
    with patch("core.portscan.asyncio.open_connection", side_effect=slow_open):
        result = await scan_ports(host, ports, sem, timeout=1.0)
    assert len(result) == len(ports)
    assert peak <= cap, f"semaphore exceeded: peak={peak}, cap={cap}"


@pytest.mark.asyncio
async def test_empty_port_list_yields_empty_result():
    """Scanning no ports is a no-op, not an error."""

    host = Host(ip="127.0.0.1", alive=True, discovered_at=datetime.now(timezone.utc))
    sem = asyncio.Semaphore(10)
    assert await scan_ports(host, [], sem, timeout=0.1) == []
