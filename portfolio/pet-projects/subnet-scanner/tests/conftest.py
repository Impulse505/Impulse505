"""Shared fixtures for the test suite."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.models import (
    CveMatch,
    Host,
    HostResult,
    OpenPort,
    ScanResult,
    ServiceInfo,
)


@pytest.fixture
def sample_result() -> ScanResult:
    """One host, one open port, one CVE — the happy-path render fixture."""

    started = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 1, 1, 10, 0, 3, tzinfo=timezone.utc)
    host = Host(
        ip="10.0.0.42",
        alive=True,
        discovered_at=started,
        mac="aa:bb:cc:dd:ee:ff",
        hostname="WEBSRV",
        method="tcp+arp",
    )
    service = ServiceInfo(
        name="apache",
        version="2.4.49",
        raw_banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.49",
    )
    cve = CveMatch(
        cve_id="CVE-2021-41773",
        cvss_score=7.5,
        cvss_severity="HIGH",
        summary="Path traversal in Apache HTTP Server 2.4.49.",
        published=datetime(2021, 10, 5, tzinfo=timezone.utc),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    )
    host_result = HostResult(host=host, open_ports=[(OpenPort(port=80), service, [cve])])
    return ScanResult(started_at=started, finished_at=finished, hosts=[host_result])


@pytest.fixture
def firewalled_result() -> ScanResult:
    """A live host with zero open ports, found only via ARP+NBNS."""

    started = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    host = Host(
        ip="192.168.1.50",
        alive=True,
        discovered_at=started,
        mac="00:11:22:33:44:55",
        hostname="DESKTOP-ABC123",
        method="arp+nbns",
    )
    host_result = HostResult(host=host, open_ports=[])
    return ScanResult(started_at=started, finished_at=started, hosts=[host_result])
