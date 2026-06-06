"""Unit tests for amhf.storage.sqlite_sink.SQLiteSink."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from amhf.storage import AttemptKind, AttemptRecord, SQLiteSink, StorageError


def _rec(run_id: str, n: int) -> AttemptRecord:
    return AttemptRecord(
        run_id=run_id,
        attempt_no=n,
        target_id="dvwa-modsec",
        payload_id=f"sqli_{n:03d}",
        payload_text="' OR 1=1 --",
        chromosome=["url_encode"],
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


def test_sqlite_round_trip(tmp_path: Path) -> None:
    sink = SQLiteSink(tmp_path)
    sink.open("run-1")
    for i in range(5):
        sink.write(_rec("run-1", i))
    sink.close()

    db_path = tmp_path / "attempts.sqlite3"
    assert db_path.exists()

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM attempts WHERE run_id = ?", ("run-1",))
        (n,) = cur.fetchone()
        assert n == 5
        # Index must exist.
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
            ("idx_attempts_run_attempt",),
        )
        assert cur.fetchone() is not None
        # Columns: 18 total.
        cur.execute("PRAGMA table_info(attempts)")
        columns = [row[1] for row in cur.fetchall()]
        assert set(columns) == set(AttemptRecord.model_fields)
        # chromosome stored as JSON-encoded TEXT.
        cur.execute("SELECT chromosome FROM attempts ORDER BY attempt_no LIMIT 1")
        (chromo,) = cur.fetchone()
        assert json.loads(chromo) == ["url_encode"]
    finally:
        conn.close()


def test_sqlite_max_attempt_no_resume(tmp_path: Path) -> None:
    sink = SQLiteSink(tmp_path)
    sink.open("run-r")
    for i in range(3):
        sink.write(_rec("run-r", i))
    sink.flush()
    assert sink.max_attempt_no("run-r") == 2
    assert sink.max_attempt_no("run-other") is None
    sink.close()


def test_sqlite_run_id_mismatch_raises(tmp_path: Path) -> None:
    sink_a = SQLiteSink(tmp_path)
    sink_a.open("run-A")
    sink_a.write(_rec("run-A", 0))
    sink_a.close()
    sink_b = SQLiteSink(tmp_path)
    with pytest.raises(StorageError):
        sink_b.open("run-B")


def test_sqlite_buffering_flushes_on_close(tmp_path: Path) -> None:
    sink = SQLiteSink(tmp_path, flush_every=100)
    sink.open("run-buf")
    for i in range(5):
        sink.write(_rec("run-buf", i))
    # Не вызываем flush() явно — close() должен дочистить.
    sink.close()
    conn = sqlite3.connect(tmp_path / "attempts.sqlite3")
    try:
        (n,) = conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE run_id = ?", ("run-buf",),
        ).fetchone()
    finally:
        conn.close()
    assert n == 5


def test_sqlite_write_before_open_raises(tmp_path: Path) -> None:
    sink = SQLiteSink(tmp_path)
    with pytest.raises(StorageError):
        sink.write(_rec("run-x", 0))
