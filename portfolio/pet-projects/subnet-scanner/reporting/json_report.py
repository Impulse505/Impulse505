"""JSON export of scan results."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from core.models import ScanResult


def _default(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _to_payload(result: ScanResult) -> dict:
    """Build a plain-dict payload preserving the dataclass shape."""

    hosts = []
    for host_result in result.hosts:
        ports = []
        for open_port, service, cves in host_result.open_ports:
            ports.append(
                {
                    "port": open_port.port,
                    "protocol": open_port.protocol,
                    "service": asdict(service) if service is not None else None,
                    "cves": [asdict(cve) for cve in cves],
                }
            )
        hosts.append({"host": asdict(host_result.host), "open_ports": ports})
    return {
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "hosts": hosts,
    }


def export_json(result: ScanResult, path: Path) -> None:
    """Write the scan result to ``path`` as pretty-printed JSON.

    Args:
        result: Scan result to serialize.
        path: Destination file path. Parent directories are created if missing.
    """

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _to_payload(result)
    path.write_text(json.dumps(payload, indent=2, default=_default), encoding="utf-8")


def to_json_string(result: ScanResult) -> str:
    """Return the JSON payload as a string (used by ``--output both``)."""

    return json.dumps(_to_payload(result), indent=2, default=_default)
