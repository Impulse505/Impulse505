"""Dataclasses describing scanner inputs and outputs.

These types are deliberately plain so they round-trip cleanly through JSON
and play nicely with `rich` rendering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Host:
    """A network host considered by the scanner.

    Attributes:
        ip: IPv4 address as dotted string.
        alive: Whether host discovery considered the host reachable.
        discovered_at: When the host was confirmed alive.
        mac: Layer-2 hardware address when known (from the ARP cache or an
            NBNS reply), else ``None``. Present for local-subnet hosts only.
        hostname: Host/computer name when discovery learned one (e.g. via an
            NBNS node-status reply), else ``None``.
        method: How liveness was established — ``"tcp"`` (probe answered),
            ``"arp"`` (found in the neighbour cache despite a silent firewall),
            ``"nbns"`` (answered a NetBIOS node-status query), or a ``"+"``
            join of these when several signals agreed.
    """

    ip: str
    alive: bool
    discovered_at: datetime
    mac: str | None = None
    hostname: str | None = None
    method: str = "tcp"


@dataclass
class OpenPort:
    """An open TCP/UDP port on a host.

    Attributes:
        port: Port number (1-65535).
        protocol: Transport protocol; currently only ``tcp`` is implemented.
    """

    port: int
    protocol: str = "tcp"


@dataclass
class ServiceInfo:
    """Result of fingerprinting an open port.

    Attributes:
        name: Identified service name (``ssh``, ``http``, ``ftp`` …) or
            ``"unknown"`` when the banner could not be classified.
        version: Free-form version string extracted from the banner, or
            ``None`` if version detection failed.
        raw_banner: First bytes received from the server, decoded as latin-1.
            Used both for display and for downstream CVE matching.
    """

    name: str
    version: str | None
    raw_banner: str


@dataclass
class CveMatch:
    """A CVE record correlated to an identified service.

    Attributes:
        cve_id: NVD identifier such as ``CVE-2021-41773``.
        cvss_score: Highest CVSS base score available (v3.1 preferred,
            falling back to v3.0 / v2.0). ``0.0`` if no score is published.
        cvss_severity: Severity bucket (``CRITICAL``/``HIGH``/``MEDIUM``/
            ``LOW``/``NONE``) derived from the chosen CVSS score.
        summary: Short human-readable description; typically the first
            sentence of the NVD description.
        published: ``datetime`` parsed from the NVD ``published`` field.
        references: Up to three reference URLs from the record.
    """

    cve_id: str
    cvss_score: float
    cvss_severity: str
    summary: str
    published: datetime
    references: list[str] = field(default_factory=list)


@dataclass
class HostResult:
    """Per-host scan output: open ports, optional service info, optional CVEs.

    Each entry is a 3-tuple ``(OpenPort, ServiceInfo | None, list[CveMatch])``.
    The ``list[CveMatch]`` is always present but may be empty when CVE lookup
    is disabled, when the service version is unknown, or when no matches
    were found.
    """

    host: Host
    open_ports: list[tuple[OpenPort, ServiceInfo | None, list[CveMatch]]] = field(
        default_factory=list
    )


@dataclass
class ScanResult:
    """Top-level scan output rendered by reporting backends."""

    started_at: datetime
    finished_at: datetime
    hosts: list[HostResult] = field(default_factory=list)


@dataclass
class ScanConfig:
    """Runtime configuration assembled from CLI arguments.

    Attributes:
        targets: Resolved list of IP addresses (dotted strings).
        ports: Ports to scan on every alive host.
        timeout: Per-connection timeout in seconds for port scanning.
        concurrency: Maximum number of in-flight connections (semaphore size).
        skip_banner: When ``True``, fingerprinting is bypassed.
        profile: Symbolic name of the chosen profile (informational).
        stealth_delay: Optional per-connection sleep used by the ``stealth``
            profile to throttle scanning. ``0`` disables throttling.
        enable_cve: When ``True``, identified services are looked up against
            the NVD database.
        nvd_api_key: Optional API key that lifts NVD rate limits.
        cve_cache_path: SQLite file used for CVE response caching.
        use_arp: When ``True``, discovery augments TCP probing with the OS
            ARP cache to find firewalled local hosts that drop TCP.
        use_nbns: When ``True``, discovery sends NBNS node-status queries to
            find Windows hosts and learn their computer names.
    """

    targets: list[str]
    ports: list[int]
    timeout: float = 1.0
    concurrency: int = 200
    skip_banner: bool = False
    profile: str = "fast"
    stealth_delay: float = 0.0
    enable_cve: bool = True
    nvd_api_key: str | None = None
    cve_cache_path: str = "nvd_cache.db"
    use_arp: bool = True
    use_nbns: bool = True
