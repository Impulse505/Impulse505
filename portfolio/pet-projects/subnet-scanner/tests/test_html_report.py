"""Smoke tests for the HTML report renderer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.models import (
    CveMatch,
    Host,
    HostResult,
    OpenPort,
    ScanResult,
    ServiceInfo,
)
from reporting.html_report import export_html, render_html


def _make_result() -> ScanResult:
    started = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 1, 1, 10, 0, 5, tzinfo=timezone.utc)
    host = Host(ip="10.0.0.42", alive=True, discovered_at=started)
    service = ServiceInfo(
        name="apache", version="2.4.49", raw_banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.49"
    )
    cve = CveMatch(
        cve_id="CVE-2021-41773",
        cvss_score=7.5,
        cvss_severity="HIGH",
        summary="Path traversal in Apache HTTP Server 2.4.49.",
        published=datetime(2021, 10, 5, tzinfo=timezone.utc),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    )
    host_result = HostResult(
        host=host,
        open_ports=[(OpenPort(port=80), service, [cve])],
    )
    return ScanResult(started_at=started, finished_at=finished, hosts=[host_result])


def test_render_html_contains_host_and_cve():
    """Render output contains host IP, service, and CVE id."""

    html = render_html(_make_result())
    assert "10.0.0.42" in html
    assert "apache" in html
    assert "CVE-2021-41773" in html
    assert "HIGH" in html
    assert "<!doctype html>" in html.lower()


def test_render_html_handles_empty_scan():
    """A result with no hosts still renders without error."""

    empty = ScanResult(
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        hosts=[],
    )
    html = render_html(empty)
    assert "No live hosts" in html


def test_export_html_writes_file(tmp_path: Path):
    """`export_html` writes a non-trivial file to the requested path."""

    out = tmp_path / "subdir" / "report.html"
    export_html(_make_result(), out)
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "CVE-2021-41773" in text
    assert len(text) > 1000
