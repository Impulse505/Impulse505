"""Unit tests for the rich terminal renderer."""

from __future__ import annotations

import io
from datetime import datetime, timezone

from rich.console import Console

from core.models import Host, HostResult, OpenPort, ScanResult, ServiceInfo
from reporting.terminal import print_scan_result


def _render(result: ScanResult) -> str:
    console = Console(file=io.StringIO(), width=200, force_terminal=False)
    print_scan_result(result, console=console)
    return console.file.getvalue()


def test_renders_host_port_and_cve(sample_result: ScanResult):
    """The table carries the host, service, version and CVE id."""

    out = _render(sample_result)
    assert "Scan complete" in out
    assert "10.0.0.42" in out
    assert "apache" in out
    assert "2.4.49" in out
    assert "CVE-2021-41773" in out


def test_renders_host_metadata(sample_result: ScanResult):
    """Hostname, MAC and non-default detection method appear in the cell."""

    out = _render(sample_result)
    assert "WEBSRV" in out
    assert "aa:bb:cc:dd:ee:ff" in out
    assert "via tcp+arp" in out


def test_firewalled_host_shown_with_no_ports(firewalled_result: ScanResult):
    """A live, port-less host is still listed and flagged as firewalled."""

    out = _render(firewalled_result)
    assert "behind a firewall" in out
    assert "host up" in out
    assert "DESKTOP-ABC123" in out
    assert "00:11:22:33:44:55" in out
    assert "via arp+nbns" in out


def test_empty_result_reports_no_hosts():
    """An empty scan prints a friendly message instead of a table."""

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    out = _render(ScanResult(started_at=now, finished_at=now, hosts=[]))
    assert "No live hosts" in out


def test_binary_banner_is_sanitised_for_display():
    """A binary SMB banner renders as ASCII — high bytes would crash a
    non-UTF-8 console, so they must never reach the output."""

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    host = Host(ip="10.0.0.7", alive=True, discovered_at=now)
    service = ServiceInfo("smb", "SMB 3.1.1", "\xfeSMB\x00\x00\xff\xfe binary")
    result = ScanResult(
        started_at=now,
        finished_at=now,
        hosts=[HostResult(host=host, open_ports=[(OpenPort(port=445), service, [])])],
    )
    out = _render(result)
    assert "smb" in out
    assert "\xfe" not in out  # high latin-1 bytes stripped
    assert "\xff" not in out
