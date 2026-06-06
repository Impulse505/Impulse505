"""HTML report renderer built on Jinja2.

The renderer produces a single self-contained HTML file with embedded CSS
so the report can be opened directly from the filesystem and emailed as an
artifact. CVEs per service are sorted by CVSS descending so the most
severe issues surface first.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import ScanResult

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
_BANNER_LIMIT = 120


def _banner_short(text: str) -> str:
    """Single-line, length-capped version of a banner suitable for table cells."""

    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    if len(text) <= _BANNER_LIMIT:
        return text
    return text[: _BANNER_LIMIT - 1] + "..."


def _build_context(result: ScanResult) -> dict:
    """Flatten the scan result into a Jinja-friendly dict tree."""

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    hosts_ctx = []
    total_open = 0
    total_cves = 0

    for host_result in result.hosts:
        host_open_ports = []
        host_cve_count = 0
        for open_port, service, cves in host_result.open_ports:
            cves_sorted = sorted(cves, key=lambda c: c.cvss_score, reverse=True)
            host_cve_count += len(cves_sorted)
            for cve in cves_sorted:
                severity_counts[cve.cvss_severity] = severity_counts.get(cve.cvss_severity, 0) + 1
            host_open_ports.append(
                {
                    "port": open_port.port,
                    "protocol": open_port.protocol,
                    "service_name": service.name if service else "-",
                    "service_version": service.version if service else None,
                    "banner_short": _banner_short(service.raw_banner) if service else "",
                    "cves": cves_sorted,
                }
            )
        total_open += len(host_result.open_ports)
        total_cves += host_cve_count
        hosts_ctx.append(
            {
                "ip": host_result.host.ip,
                "hostname": host_result.host.hostname,
                "mac": host_result.host.mac,
                "method": host_result.host.method,
                "open_ports": host_open_ports,
                "total_cves": host_cve_count,
            }
        )

    # Live hosts with no TCP signal were found purely by ARP/NBNS — i.e.
    # machines hiding behind a firewall that drops every probe.
    firewalled = sum(1 for h in result.hosts if "tcp" not in h.host.method)
    duration = (result.finished_at - result.started_at).total_seconds()
    return {
        "started_at_human": result.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "finished_at_human": result.finished_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "duration_seconds": f"{duration:.2f}",
        "total_hosts": len(result.hosts),
        "total_open_ports": total_open,
        "total_cves": total_cves,
        "firewalled": firewalled,
        "severity_counts": severity_counts,
        "hosts": hosts_ctx,
    }


def render_html(result: ScanResult, templates_dir: Path | None = None) -> str:
    """Return the rendered HTML report as a string."""

    env = Environment(
        loader=FileSystemLoader(str(templates_dir or _TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    return template.render(**_build_context(result))


def export_html(result: ScanResult, path: Path, templates_dir: Path | None = None) -> None:
    """Write the rendered report to ``path``.

    Args:
        result: Scan result to render.
        path: Destination ``.html`` file. Parent directories are created if
            necessary.
        templates_dir: Override the default ``templates/`` location. Mostly
            useful for tests.
    """

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result, templates_dir=templates_dir), encoding="utf-8")
