"""Terminal output: a `rich.Table` rendering of the scan result."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from core.models import Host, ScanResult

BANNER_TRUNCATE: int = 50

_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "NONE": "dim",
}


def _printable(text: str) -> str:
    """Reduce text to printable ASCII for terminal display.

    Binary banners (SMB, MSRPC) and high latin-1 bytes are not meaningful on
    screen and, worse, crash a non-UTF-8 console (e.g. Windows cp1251) on
    write. The full raw banner is still preserved verbatim in the JSON and
    HTML reports — this sanitising is display-only.
    """

    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)


def _truncate(text: str, limit: int = BANNER_TRUNCATE) -> str:
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", " ")
    text = _printable(text)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "..."


def _format_cves(cves: list, limit: int = 3) -> str:
    """Return a compact CVE summary cell. Worst severity bubbles up first."""

    if not cves:
        return ""
    top = cves[:limit]
    parts: list[str] = []
    for cve in top:
        style = _SEVERITY_STYLE.get(cve.cvss_severity, "white")
        score = f"{cve.cvss_score:.1f}" if cve.cvss_score else "?"
        parts.append(f"[{style}]{cve.cve_id} ({score})[/]")
    extra = len(cves) - len(top)
    if extra > 0:
        parts.append(f"[dim]+{extra} more[/]")
    return "\n".join(parts)


def _worst_severity(cves: list) -> str:
    ranking = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1}
    return max((c.cvss_severity for c in cves), key=lambda s: ranking.get(s, 0), default="")


def _host_cell(host: Host) -> str:
    """Compose the multi-line Host cell: ip plus hostname/mac/method if known."""

    lines = [host.ip]
    if host.hostname:
        lines.append(f"[cyan]{host.hostname}[/]")
    if host.mac:
        lines.append(f"[dim]{host.mac}[/]")
    if host.method and host.method != "tcp":
        lines.append(f"[dim]via {host.method}[/]")
    return "\n".join(lines)


def print_scan_result(result: ScanResult, console: Console | None = None) -> None:
    """Render a scan result to the terminal as a rich table.

    Args:
        result: Populated scan output.
        console: Optional pre-built console (used in tests). When omitted
            a fresh one is created with default styling.
    """

    console = console or Console()
    duration = (result.finished_at - result.started_at).total_seconds()
    total_open = sum(len(h.open_ports) for h in result.hosts)
    total_cves = sum(len(cves) for h in result.hosts for _, _, cves in h.open_ports)
    # Hosts found only by ARP/NBNS (no TCP signal) are live machines that
    # dropped every probe — the firewall-aware discovery's headline result.
    firewalled = sum(1 for h in result.hosts if "tcp" not in h.host.method)
    summary = (
        f"[bold]Scan complete[/] - {len(result.hosts)} live host(s), "
        f"{total_open} open port(s), {total_cves} CVE(s), {duration:.2f}s"
    )
    if firewalled:
        summary += f"\n[dim]{firewalled} host(s) found behind a firewall via ARP/NBNS[/dim]"
    console.print(summary)

    if not result.hosts:
        console.print("[dim]No live hosts.[/dim]")
        return

    table = Table(show_lines=True, header_style="bold cyan")
    table.add_column("Host", style="white", no_wrap=True)
    table.add_column("Port", justify="right", style="green")
    table.add_column("Service", style="magenta")
    table.add_column("Version", style="yellow")
    table.add_column("Banner", style="dim")
    table.add_column("CVEs", style="white")

    for host_result in result.hosts:
        host_cell = _host_cell(host_result.host)
        if not host_result.open_ports:
            # Alive but every port filtered/closed — still worth showing.
            table.add_row(host_cell, "—", "[dim]host up — no open ports[/dim]", "", "", "")
            continue
        first = True
        for open_port, service, cves in host_result.open_ports:
            name = service.name if service else "-"
            version = _printable(
                (service.version if service and service.version else "") if service else ""
            )
            banner = _truncate(service.raw_banner) if service else ""
            table.add_row(
                host_cell if first else "",
                str(open_port.port),
                name,
                version,
                banner,
                _format_cves(cves),
            )
            first = False

    console.print(table)
