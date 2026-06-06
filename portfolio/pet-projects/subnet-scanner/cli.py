"""Command-line entry point for the subnet scanner."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

from core.models import ScanConfig
from core.orchestrator import run_scan
from core.portscan import TOP_100_PORTS, TOP_1000_PORTS
from reporting.html_report import export_html
from reporting.json_report import export_json
from reporting.terminal import print_scan_result

logger = logging.getLogger("subnet_scanner")

OUTPUT_CHOICES = ("terminal", "json", "html", "both", "all")


@dataclass(frozen=True)
class _Profile:
    timeout: float
    ports: list[int]
    stealth_delay: float = 0.0


PROFILES: dict[str, _Profile] = {
    "fast": _Profile(timeout=0.5, ports=TOP_100_PORTS),
    "full": _Profile(timeout=2.0, ports=TOP_1000_PORTS),
    "stealth": _Profile(timeout=3.0, ports=TOP_100_PORTS, stealth_delay=0.05),
}


def _expand_targets(spec: str) -> list[str]:
    """Expand a target spec into individual IPv4 addresses.

    Accepted forms:
        * Single IP — ``192.168.1.10``
        * Last-octet range — ``192.168.1.1-50``
        * CIDR — ``192.168.1.0/24``
    """

    spec = spec.strip()
    if "/" in spec:
        network = ipaddress.ip_network(spec, strict=False)
        return (
            [str(ip) for ip in network.hosts()]
            if network.num_addresses > 2
            else [str(ip) for ip in network]
        )
    if "-" in spec:
        match = re.fullmatch(r"(\d+\.\d+\.\d+)\.(\d+)-(\d+)", spec)
        if not match:
            raise argparse.ArgumentTypeError(f"unsupported range syntax: {spec!r}")
        prefix, lo, hi = match.group(1), int(match.group(2)), int(match.group(3))
        if not (0 <= lo <= hi <= 255):
            raise argparse.ArgumentTypeError(f"invalid range bounds in {spec!r}")
        return [f"{prefix}.{i}" for i in range(lo, hi + 1)]
    # Single address — validate it.
    ipaddress.IPv4Address(spec)
    return [spec]


def _parse_ports(spec: str) -> list[int]:
    """Parse ``--ports`` syntax.

    Accepts ``top100``, ``top1000``, or a comma-separated list of port
    numbers and ``a-b`` ranges. Ports are deduplicated and sorted.
    """

    spec = spec.strip().lower()
    if spec == "top100":
        return list(TOP_100_PORTS)
    if spec == "top1000":
        return list(TOP_1000_PORTS)

    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if not (1 <= lo <= hi <= 65535):
                raise argparse.ArgumentTypeError(f"invalid port range: {chunk!r}")
            ports.update(range(lo, hi + 1))
        else:
            value = int(chunk)
            if not (1 <= value <= 65535):
                raise argparse.ArgumentTypeError(f"port out of range: {value}")
            ports.add(value)
    return sorted(ports)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subnet-scanner",
        description="Async network reconnaissance with banner-based service identification.",
    )
    parser.add_argument("--target", required=True, help="IP, range (a.b.c.1-50), or CIDR")
    parser.add_argument(
        "--ports",
        default=None,
        help="Ports: 'top100', 'top1000', or a list like '22,80,443,8000-8100'.",
    )
    parser.add_argument(
        "--profile",
        default="fast",
        choices=sorted(PROFILES),
        help="Scan profile (default: fast)",
    )
    parser.add_argument(
        "--output",
        default="terminal",
        choices=OUTPUT_CHOICES,
        help=(
            "Where to emit results: terminal | json | html | both (terminal+json) | "
            "all (terminal+json+html). Default: terminal."
        ),
    )
    parser.add_argument("--threads", type=int, default=200, help="Semaphore size (default: 200)")
    parser.add_argument("--timeout", type=float, default=None, help="Per-port timeout in seconds")
    parser.add_argument("--no-banner", action="store_true", help="Skip fingerprinting")
    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip CVE lookup (NVD requests still go out otherwise)",
    )
    parser.add_argument(
        "--no-arp",
        action="store_true",
        help="Skip ARP-cache discovery (the signal that finds firewalled local hosts)",
    )
    parser.add_argument(
        "--no-nbns",
        action="store_true",
        help="Skip NBNS node-status discovery (UDP/137) of Windows hosts",
    )
    parser.add_argument(
        "--nvd-api-key",
        default=None,
        help="NVD API key (overrides $NVD_API_KEY); lifts the 5 req/30s rate limit",
    )
    parser.add_argument(
        "--cve-cache",
        type=Path,
        default=Path("nvd_cache.db"),
        help="SQLite path for the CVE cache (default: nvd_cache.db)",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=Path("scan_results/last.json"),
        help="JSON output destination",
    )
    parser.add_argument(
        "--html-output",
        type=Path,
        default=Path("scan_results/last.html"),
        help="HTML output destination",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


def _build_config(args: argparse.Namespace) -> ScanConfig:
    profile = PROFILES[args.profile]
    ports = _parse_ports(args.ports) if args.ports else list(profile.ports)
    timeout = args.timeout if args.timeout is not None else profile.timeout
    targets = _expand_targets(args.target)
    return ScanConfig(
        targets=targets,
        ports=ports,
        timeout=timeout,
        concurrency=args.threads,
        skip_banner=args.no_banner,
        profile=args.profile,
        stealth_delay=profile.stealth_delay,
        enable_cve=not args.no_cve and not args.no_banner,
        nvd_api_key=args.nvd_api_key or os.environ.get("NVD_API_KEY"),
        cve_cache_path=str(args.cve_cache),
        use_arp=not args.no_arp,
        use_nbns=not args.no_nbns,
    )


def _wants(args_output: str, kind: str) -> bool:
    """Whether the chosen ``--output`` value should produce ``kind`` artefact."""

    if args_output == "all":
        return True
    if args_output == "both":
        return kind in ("terminal", "json")
    return args_output == kind


async def _run(args: argparse.Namespace) -> int:
    console = Console()
    config = _build_config(args)

    discovery = "tcp" + ("+arp" if config.use_arp else "") + ("+nbns" if config.use_nbns else "")
    console.print(
        f"[bold cyan]subnet-scanner[/] | profile=[bold]{config.profile}[/] | "
        f"{len(config.targets)} target(s) | {len(config.ports)} port(s) | "
        f"timeout={config.timeout}s | concurrency={config.concurrency} | "
        f"cve={'on' if config.enable_cve else 'off'} | discovery={discovery}"
    )

    progress_columns = (
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    )
    with Progress(*progress_columns, console=console, transient=False) as progress:
        result = await run_scan(config, progress=progress)

    if _wants(args.output, "terminal"):
        print_scan_result(result, console=console)
    if _wants(args.output, "json"):
        export_json(result, args.output_file)
        console.print(f"[green]JSON written:[/green] {args.output_file}")
    if _wants(args.output, "html"):
        export_html(result, args.html_output)
        console.print(f"[green]HTML written:[/green] {args.html_output}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
