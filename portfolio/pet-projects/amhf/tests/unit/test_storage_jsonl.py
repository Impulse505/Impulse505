"""Unit tests for amhf.storage.jsonl_sink.JSONLSink."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from amhf.storage import AttemptKind, AttemptRecord, JSONLSink, StorageError


def _rec(run_id: str, n: int) -> AttemptRecord:
    return AttemptRecord(
        run_id=run_id,
        attempt_no=n,
        target_id="dvwa-modsec",
        payload_id=f"sqli_{n:03d}",
        payload_text="' OR 1=1 --",
        chromosome=["url_encode", "case_toggle"],
        mutated_request_summary=f"GET /v?{n}",
        status_code=200,
        response_time_ms=12.0 + n,
        waf_blocked=False,
        waf_signature_hit=None,
        exploit_confirmed=True,
        oracle_reason="flag_marker",
        bypass=True,
        ucb_reward=1,
        attempt_kind=AttemptKind.MUTATION,
        seed=42,
    )


def test_jsonl_round_trip(tmp_path: Path) -> None:
    sink = JSONLSink(tmp_path)
    sink.open("run-1")
    for i in range(5):
        sink.write(_rec("run-1", i))
    sink.close()

    path = tmp_path / "attempts.jsonl"
    assert path.exists()

    raw = path.read_bytes()
    # Разделитель обязан быть только \n, не \r\n.
    assert b"\r\n" not in raw

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    for i, line in enumerate(lines):
        obj = json.loads(line)
        assert obj["run_id"] == "run-1"
        assert obj["attempt_no"] == i
        assert obj["chromosome"] == ["url_encode", "case_toggle"]
        assert set(obj.keys()) == set(AttemptRecord.model_fields)


def test_jsonl_buffering(tmp_path: Path) -> None:
    sink = JSONLSink(tmp_path, flush_every=10)
    sink.open("run-2")
    for i in range(7):
        sink.write(_rec("run-2", i))
    sink.close()
    lines = (tmp_path / "attempts.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 7


def test_jsonl_write_before_open_raises(tmp_path: Path) -> None:
    sink = JSONLSink(tmp_path)
    with pytest.raises(StorageError):
        sink.write(_rec("run-x", 0))
