"""Generate the committed demo artefacts (terminal SVG, HTML, JSON).

Run from anywhere:

    python examples/generate_demo.py

It builds a representative ``ScanResult`` — a Linux server with real CVEs, a
fully firewalled Windows workstation found only via ARP/NBNS, and a Windows
server enriched by every signal — then renders it three ways. The data is
hand-built (no network), so the artefacts are deterministic and safe to
commit as the project's visual showcase.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.models import (  # noqa: E402
    CveMatch,
    Host,
    HostResult,
    OpenPort,
    ScanResult,
    ServiceInfo,
)
from reporting.html_report import export_html  # noqa: E402
from reporting.json_report import export_json  # noqa: E402

_HERE = Path(__file__).resolve().parent
_STARTED = datetime(2026, 6, 6, 14, 30, 0, tzinfo=timezone.utc)
_FINISHED = datetime(2026, 6, 6, 14, 30, 2, 400000, tzinfo=timezone.utc)


def _cve(cve_id: str, score: float, severity: str, summary: str) -> CveMatch:
    return CveMatch(
        cve_id=cve_id,
        cvss_score=score,
        cvss_severity=severity,
        summary=summary,
        published=datetime(2021, 10, 5, tzinfo=timezone.utc),
        references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
    )


def _demo_result() -> ScanResult:
    # 1) Linux server — the classic "old services with known CVEs" case.
    linux = HostResult(
        host=Host(
            ip="10.0.0.5",
            alive=True,
            discovered_at=_STARTED,
            mac="52:54:00:a1:b2:c3",
            method="tcp+arp",
        ),
        open_ports=[
            (
                OpenPort(port=22),
                ServiceInfo("ssh", "OpenSSH_7.4", "SSH-2.0-OpenSSH_7.4"),
                [_cve("CVE-2016-10009", 7.5, "HIGH", "Untrusted search path in ssh-agent.")],
            ),
            (
                OpenPort(port=80),
                ServiceInfo(
                    "http", "Apache/2.4.49 (Unix)", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49"
                ),
                [
                    _cve(
                        "CVE-2021-42013",
                        9.8,
                        "CRITICAL",
                        "Path traversal & RCE in Apache 2.4.49/2.4.50.",
                    ),
                    _cve(
                        "CVE-2021-41773",
                        7.5,
                        "HIGH",
                        "Path traversal in Apache HTTP Server 2.4.49.",
                    ),
                ],
            ),
            (
                OpenPort(port=3306),
                ServiceInfo("mysql", "5.7.33", "5.7.33-log"),
                [_cve("CVE-2021-2154", 6.5, "MEDIUM", "MySQL Server DML privilege escalation.")],
            ),
        ],
    )

    # 2) The headline: a default Windows box that drops every probe but is
    #    still found — and named — purely from ARP + NBNS.
    firewalled = HostResult(
        host=Host(
            ip="10.0.0.20",
            alive=True,
            discovered_at=_STARTED,
            mac="00:1a:2b:3c:4d:5e",
            hostname="DESKTOP-FIN01",
            method="arp+nbns",
        ),
        open_ports=[],
    )

    # 3) A Windows server seen by every signal, with a binary-probe banner.
    windows = HostResult(
        host=Host(
            ip="10.0.0.25",
            alive=True,
            discovered_at=_STARTED,
            mac="00:0c:29:7f:8e:9d",
            hostname="WIN-DC01",
            method="tcp+arp+nbns",
        ),
        open_ports=[
            (OpenPort(port=445), ServiceInfo("smb", "SMB 3.1.1", "SMB2 NEGOTIATE response"), []),
            (OpenPort(port=3389), ServiceInfo("rdp", None, ""), []),
        ],
    )

    return ScanResult(
        started_at=_STARTED, finished_at=_FINISHED, hosts=[linux, firewalled, windows]
    )


def main() -> None:
    import io

    from rich.console import Console

    from reporting.terminal import print_scan_result

    result = _demo_result()

    # Record into a buffer rather than the real stdout, so the SVG export is
    # independent of the host terminal's code page (Windows consoles choke on
    # non-ASCII banner bytes).
    console = Console(record=True, width=118, file=io.StringIO())
    print_scan_result(result, console=console)
    console.save_svg(str(_HERE / "terminal.svg"), title="subnet-scanner")

    export_html(result, _HERE / "report.html")
    export_json(result, _HERE / "scan.json")
    print(f"Wrote: {_HERE / 'terminal.svg'}, {_HERE / 'report.html'}, {_HERE / 'scan.json'}")


if __name__ == "__main__":
    main()
