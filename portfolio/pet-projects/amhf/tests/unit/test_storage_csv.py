"""Unit tests for amhf.storage.csv_sink.CSVSink."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from amhf.storage import AttemptKind, AttemptRecord, CSVSink, StorageError


def _rec(run_id: str, n: int, *, chromosome: list[str] | None = None) -> AttemptRecord:
    return AttemptRecord(
        run_id=run_id,
        attempt_no=n,
        target_id="dvwa-modsec",
        payload_id=f"sqli_{n:03d}",
        payload_text="' OR 1=1 --",
        chromosome=chromosome or ["url_encode", "case_toggle"],
        mutated_request_summary=f"GET /vuln?id={n}",
        status_code=200,
        response_time_ms=10.5 + n,
        waf_blocked=False,
        waf_signature_hit=None,
        exploit_confirmed=True,
        oracle_reason="flag_marker",
        bypass=True,
        ucb_reward=1,
        attempt_kind=AttemptKind.MUTATION,
        seed=42,
    )


def test_csv_round_trip(tmp_path: Path) -> None:
    sink = CSVSink(tmp_path)
    sink.open("run-1")
    records = [_rec("run-1", i) for i in range(5)]
    for r in records:
        sink.write(r)
    sink.close()

    csv_path = tmp_path / "attempts.csv"
    assert csv_path.exists()

    with csv_path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)

    assert len(rows) == 5
    assert set(rows[0].keys()) == set(AttemptRecord.model_fields)
    for i, row in enumerate(rows):
        assert row["run_id"] == "run-1"
        assert int(row["attempt_no"]) == i
        assert json.loads(row["chromosome"]) == ["url_encode", "case_toggle"]
        assert row["bypass"] == "true"
        assert row["waf_signature_hit"] == ""  # None -> empty
        assert row["attempt_kind"] == "mutation"


def test_csv_buffering_and_flush(tmp_path: Path) -> None:
    sink = CSVSink(tmp_path, flush_every=10)
    sink.open("run-2")
    for i in range(3):
        sink.write(_rec("run-2", i))
    # flush_every=10 -> still buffered; file may have only header.
    sink.flush()
    sink.close()
    with (tmp_path / "attempts.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 3


def test_csv_chromosome_with_unicode(tmp_path: Path) -> None:
    sink = CSVSink(tmp_path)
    sink.open("run-3")
    sink.write(_rec("run-3", 0, chromosome=["a", "b", "c"]))
    sink.close()
    with (tmp_path / "attempts.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert json.loads(rows[0]["chromosome"]) == ["a", "b", "c"]


def test_csv_write_before_open_raises(tmp_path: Path) -> None:
    sink = CSVSink(tmp_path)
    with pytest.raises(StorageError):
        sink.write(_rec("run-x", 0))
