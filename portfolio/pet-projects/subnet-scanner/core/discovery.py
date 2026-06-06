"""Firewall-aware async host discovery.

A naive "is this host up?" check sends an ICMP echo, but that needs raw
sockets (root) and is dropped by default on Windows. So discovery layers
three unprivileged signals and treats a host as alive if **any** of them
fires:

1. **TCP probe** — connect to a small bundle of commonly open ports. A
   completed handshake (open) *or* an active refusal (closed) both prove the
   host is reachable; only a timeout is inconclusive. As a side effect every
   probe forces the kernel to ARP-resolve the target, priming signal #2.
2. **ARP cache** (``arp.py``) — read the OS neighbour table. A default
   Windows host silently *drops* TCP, so it looks dead to signal #1, but it
   still answered the ARP "who-has" at layer 2 and now sits in the cache with
   a real MAC. This is what lets the scanner see fully firewalled hosts on
   the local subnet.
3. **NBNS node status** (``nbns.py``) — a UDP/137 query that many Windows
   hosts answer even with every TCP port closed, yielding the computer name
   and adapter MAC.

Signals #2 and #3 are why this scanner finds Windows workstations that a
plain TCP/ICMP sweep reports as down.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Awaitable, Callable

from .arp import read_neighbor_table
from .models import Host
from .nbns import nbns_query

logger = logging.getLogger(__name__)

# Probe bundle skewed toward what a Windows LAN actually exposes: SMB,
# NetBIOS, RPC and RDP first, then the classic web/SSH ports.
DISCOVERY_PORTS: tuple[int, ...] = (445, 139, 135, 3389, 80, 443, 22, 5985)
DISCOVERY_TIMEOUT: float = 0.5
NBNS_MIN_TIMEOUT: float = 1.0

ProbeCallback = Callable[[str, bool], None]
NeighborReader = Callable[[], Awaitable[dict[str, str]]]
NbnsQuerier = Callable[[str, float], Awaitable[tuple[str | None, str | None]]]


async def _probe(ip: str, port: int, timeout: float) -> bool:
    """Probe a single TCP port. Returns True if the host is reachable."""

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except asyncio.TimeoutError:
        return False
    except ConnectionRefusedError:
        return True
    except OSError as exc:
        logger.debug("probe %s:%d failed: %s", ip, port, exc)
        return False

    try:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, OSError):
            pass
    except Exception:  # noqa: BLE001 — best-effort cleanup
        pass
    del reader
    return True


async def _is_alive(ip: str, ports: tuple[int, ...], timeout: float) -> bool:
    """Return True as soon as any probe succeeds; False if all time out."""

    tasks = [asyncio.create_task(_probe(ip, port, timeout)) for port in ports]
    try:
        for coro in asyncio.as_completed(tasks):
            if await coro:
                return True
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return False


async def host_alive(
    ip: str, ports: tuple[int, ...] = DISCOVERY_PORTS, timeout: float = DISCOVERY_TIMEOUT
) -> bool:
    """Public single-host TCP liveness check (also primes the ARP cache)."""

    return await _is_alive(ip, ports, timeout)


def _assemble_hosts(
    targets: list[str],
    tcp_alive: dict[str, bool],
    neighbor: dict[str, str],
    nbns: dict[str, tuple[str | None, str | None]],
    now: datetime,
) -> list[Host]:
    """Fuse the three discovery signals into ``Host`` records.

    A target is alive if any signal fired. MAC prefers the ARP cache (always
    the local adapter) over the NBNS-reported address; the hostname can only
    come from NBNS. ``method`` records which signals agreed, e.g. ``tcp+arp``.
    """

    hosts: list[Host] = []
    for ip in targets:
        signals: list[str] = []
        if tcp_alive.get(ip):
            signals.append("tcp")
        arp_mac = neighbor.get(ip)
        if arp_mac is not None:
            signals.append("arp")
        nb_name, nb_mac = nbns.get(ip, (None, None))
        if nb_name is not None or nb_mac is not None:
            signals.append("nbns")
        if not signals:
            continue
        hosts.append(
            Host(
                ip=ip,
                alive=True,
                discovered_at=now,
                mac=arp_mac or nb_mac,
                hostname=nb_name,
                method="+".join(signals),
            )
        )
    return hosts


async def discover_hosts(
    targets: list[str],
    ports: tuple[int, ...] = DISCOVERY_PORTS,
    timeout: float = DISCOVERY_TIMEOUT,
    concurrency: int = 256,
    *,
    use_arp: bool = True,
    use_nbns: bool = True,
    on_probe: ProbeCallback | None = None,
    neighbor_reader: NeighborReader | None = None,
    nbns_querier: NbnsQuerier | None = None,
) -> list[Host]:
    """Probe each candidate IP and return the hosts that responded to any signal.

    Args:
        targets: IPv4 addresses as dotted strings.
        ports: TCP ports to probe per host.
        timeout: Per-port probe timeout in seconds.
        concurrency: Cap on simultaneous probes.
        use_arp: Augment liveness with the OS neighbour (ARP) cache — finds
            firewalled local hosts that drop TCP. Reads nothing off the wire.
        use_nbns: Augment liveness with NBNS node-status queries (UDP/137) —
            finds Windows hosts and learns their computer names.
        on_probe: Optional callback invoked ``(ip, tcp_alive)`` after each
            host's TCP probe, for progress reporting.
        neighbor_reader / nbns_querier: Injection points for tests; default to
            the real ARP-cache reader and NBNS querier.

    Returns:
        ``Host`` objects (``alive=True``) for every responsive target, each
        carrying whatever MAC / hostname / detection method was learned.
    """

    if not targets:
        return []

    sem = asyncio.Semaphore(concurrency)
    tcp_alive: dict[str, bool] = {}

    async def probe(ip: str) -> None:
        async with sem:
            alive = await _is_alive(ip, ports, timeout)
        tcp_alive[ip] = alive
        if on_probe is not None:
            on_probe(ip, alive)

    await asyncio.gather(*(probe(ip) for ip in targets))

    neighbor: dict[str, str] = {}
    if use_arp:
        reader = neighbor_reader or read_neighbor_table
        try:
            neighbor = await reader()
        except Exception as exc:  # noqa: BLE001 — discovery must survive a bad table read
            logger.warning("ARP cache read failed, continuing without it: %s", exc)

    nbns_results: dict[str, tuple[str | None, str | None]] = {}
    if use_nbns:
        querier = nbns_querier or nbns_query
        nb_timeout = max(timeout, NBNS_MIN_TIMEOUT)
        nb_sem = asyncio.Semaphore(min(concurrency, 64))

        async def query(ip: str) -> None:
            async with nb_sem:
                name, mac = await querier(ip, nb_timeout)
            if name is not None or mac is not None:
                nbns_results[ip] = (name, mac)

        await asyncio.gather(*(query(ip) for ip in targets))

    return _assemble_hosts(targets, tcp_alive, neighbor, nbns_results, datetime.now(timezone.utc))
