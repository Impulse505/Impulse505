"""Unit tests for the JSON exporter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.models import Host, HostResult, OpenPort, ScanResult
from reporting.json_report import export_json, to_json_string


def test_to_json_string_preserves_shape(sample_result: ScanResult):
    """The payload round-trips through json and keeps the nested structure."""

    data = json.loads(to_json_string(sample_result))
    host = data["hosts"][0]["host"]
    assert host["ip"] == "10.0.0.42"
    assert host["mac"] == "aa:bb:cc:dd:ee:ff"
    assert host["hostname"] == "WEBSRV"
    assert host["method"] == "tcp+arp"

    port = data["hosts"][0]["open_ports"][0]
    assert port["port"] == 80
    assert port["service"]["name"] == "apache"
    assert port["cves"][0]["cve_id"] == "CVE-2021-41773"


def test_datetimes_serialized_as_iso(sample_result: ScanResult):
    data = json.loads(to_json_string(sample_result))
    assert data["started_at"].startswith("2026-01-01T")
    assert data["finished_at"].startswith("2026-01-01T")


def test_export_json_writes_file(tmp_path: Path, sample_result: ScanResult):
    out = tmp_path / "nested" / "scan.json"
    export_json(sample_result, out)
    assert out.exists()
    reloaded = json.loads(out.read_text(encoding="utf-8"))
    assert reloaded["hosts"][0]["host"]["ip"] == "10.0.0.42"


def test_none_service_serializes_as_null():
    """A port with no fingerprint serializes ``service`` as null, not a crash."""

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    host = Host(ip="10.0.0.9", alive=True, discovered_at=now)
    result = ScanResult(
        started_at=now,
        finished_at=now,
        hosts=[HostResult(host=host, open_ports=[(OpenPort(port=22), None, [])])],
    )
    data = json.loads(to_json_string(result))
    assert data["hosts"][0]["open_ports"][0]["service"] is None
