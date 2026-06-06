"""High-level pipeline gluing discovery, port scan, fingerprinting, CVE lookup."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from rich.progress import Progress, TaskID

from .cve_lookup import NvdClient
from .discovery import discover_hosts
from .fingerprint import fingerprint
from .models import (
    CveMatch,
    Host,
    HostResult,
    OpenPort,
    ScanConfig,
    ScanResult,
    ServiceInfo,
)
from .portscan import scan_ports

logger = logging.getLogger(__name__)

_PortRow = tuple[OpenPort, ServiceInfo | None, list[CveMatch]]


async def _fingerprint_host(
    host: Host,
    open_ports: list[OpenPort],
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> list[tuple[OpenPort, ServiceInfo | None]]:
    """Fingerprint every open port on a single host."""

    async def one(port: OpenPort) -> tuple[OpenPort, ServiceInfo | None]:
        async with semaphore:
            try:
                info = await fingerprint(host, port, timeout=timeout)
            except Exception as exc:  # noqa: BLE001 — never let one bad port poison the scan
                logger.warning("fingerprint %s:%d crashed: %s", host.ip, port.port, exc)
                info = None
            return (port, info)

    return await asyncio.gather(*(one(p) for p in open_ports))


async def _enrich_with_cves(
    pairs: list[tuple[OpenPort, ServiceInfo | None]],
    client: NvdClient | None,
) -> list[_PortRow]:
    """Attach a CVE list to each (port, service) tuple. Empty if no client."""

    if client is None:
        return [(port, service, []) for port, service in pairs]

    async def lookup(service: ServiceInfo | None) -> list[CveMatch]:
        if service is None:
            return []
        try:
            return await client.lookup(service)
        except Exception as exc:  # noqa: BLE001 — never let one CVE lookup kill the scan
            logger.warning("cve lookup failed for %s/%s: %s", service.name, service.version, exc)
            return []

    cve_lists = await asyncio.gather(*(lookup(s) for _, s in pairs))
    return [(port, service, cves) for (port, service), cves in zip(pairs, cve_lists, strict=True)]


async def run_scan(config: ScanConfig, progress: Progress | None = None) -> ScanResult:
    """Execute the full pipeline for the given configuration.

    Args:
        config: Resolved CLI configuration.
        progress: Optional ``rich.progress.Progress`` instance to drive a
            live status display.

    Returns:
        A populated ``ScanResult`` with one entry per host that responded.
    """

    started_at = datetime.now(timezone.utc)
    semaphore = asyncio.Semaphore(config.concurrency)

    discovery_task: TaskID | None = None
    if progress is not None:
        discovery_task = progress.add_task(
            f"Discovering hosts ({len(config.targets)})", total=len(config.targets)
        )

    alive = await _discover(config, progress, discovery_task)

    if progress is not None and discovery_task is not None:
        progress.update(discovery_task, completed=len(config.targets))

    if not alive:
        logger.info("no live hosts found")
        return ScanResult(started_at=started_at, finished_at=datetime.now(timezone.utc), hosts=[])

    scan_task: TaskID | None = None
    if progress is not None:
        scan_task = progress.add_task(
            f"Scanning {len(alive)} host(s) x {len(config.ports)} port(s)",
            total=len(alive) * len(config.ports),
        )

    if config.enable_cve:
        async with NvdClient.create(
            cache_path=config.cve_cache_path, api_key=config.nvd_api_key
        ) as cve_client:
            host_results = await _scan_with_client(
                alive, config, semaphore, progress, scan_task, cve_client
            )
    else:
        host_results = await _scan_with_client(alive, config, semaphore, progress, scan_task, None)

    return ScanResult(
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        hosts=host_results,
    )


async def _scan_with_client(
    alive: list[Host],
    config: ScanConfig,
    semaphore: asyncio.Semaphore,
    progress: Progress | None,
    scan_task: TaskID | None,
    cve_client: NvdClient | None,
) -> list[HostResult]:
    """Run port scan + fingerprint + (optional) CVE lookup for every host."""

    async def per_host(host: Host) -> HostResult:
        open_ports = await scan_ports(
            host, config.ports, semaphore, config.timeout, delay=config.stealth_delay
        )
        if progress is not None and scan_task is not None:
            progress.update(scan_task, advance=len(config.ports))
        if not open_ports:
            return HostResult(host=host, open_ports=[])
        if config.skip_banner:
            return HostResult(host=host, open_ports=[(p, None, []) for p in open_ports])
        paired = await _fingerprint_host(host, open_ports, semaphore, timeout=config.timeout * 2)
        enriched = await _enrich_with_cves(paired, cve_client)
        return HostResult(host=host, open_ports=enriched)

    return list(await asyncio.gather(*(per_host(h) for h in alive)))


async def _discover(
    config: ScanConfig,
    progress: Progress | None,
    task_id: TaskID | None,
) -> list[Host]:
    """Run discovery once, advancing the progress bar per TCP probe.

    Discovery reads the ARP cache and runs NBNS a single time after probing,
    so it must run as one batch (not per-IP) to avoid spawning the neighbour-
    table command for every target.
    """

    completed = 0

    def on_probe(_ip: str, _alive: bool) -> None:
        nonlocal completed
        if progress is not None and task_id is not None:
            completed += 1
            progress.update(task_id, completed=completed)

    return await discover_hosts(
        config.targets,
        use_arp=config.use_arp,
        use_nbns=config.use_nbns,
        on_probe=on_probe,
    )
