"""SQLiteSink — синхронный SQLite-сток для AttemptRecord.

Стратегия конкурентности
-------------------------
Сток сделан *чисто синхронным*. Из async-кода оркестратор должен
вызывать его через ``await asyncio.to_thread(sink.write, record)``,
чтобы блокирующий sqlite3 не залипал в event loop.

Файл: ``<output_dir>/attempts.sqlite3``. Одна таблица ``attempts`` со
всеми 18 полями AttemptRecord; индекс по ``(run_id, attempt_no)``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from amhf.storage.schema import AttemptRecord
from amhf.storage.sink import BufferedSink, StorageError

_FILENAME = "attempts.sqlite3"

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS attempts (
    timestamp               TEXT    NOT NULL,
    run_id                  TEXT    NOT NULL,
    attempt_no              INTEGER NOT NULL,
    target_id               TEXT    NOT NULL,
    payload_id              TEXT    NOT NULL,
    payload_text            TEXT    NOT NULL,
    chromosome              TEXT    NOT NULL,
    mutated_request_summary TEXT    NOT NULL,
    status_code             INTEGER NOT NULL,
    response_time_ms        REAL    NOT NULL,
    waf_blocked             INTEGER NOT NULL,
    waf_signature_hit       TEXT,
    exploit_confirmed       INTEGER NOT NULL,
    oracle_reason           TEXT    NOT NULL,
    bypass                  INTEGER NOT NULL,
    ucb_reward              INTEGER NOT NULL,
    attempt_kind            TEXT    NOT NULL,
    seed                    INTEGER NOT NULL
)
"""

_CREATE_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_attempts_run_attempt "
    "ON attempts(run_id, attempt_no)"
)

_INSERT_SQL = """
INSERT INTO attempts (
    timestamp, run_id, attempt_no, target_id, payload_id, payload_text,
    chromosome, mutated_request_summary, status_code, response_time_ms,
    waf_blocked, waf_signature_hit, exploit_confirmed, oracle_reason,
    bypass, ucb_reward, attempt_kind, seed
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


class SQLiteSink(BufferedSink):
    """Синхронный sqlite3-сток. Вызывайте через asyncio.to_thread в async-коде."""

    def __init__(self, output_dir: Path | str, *, flush_every: int = 1) -> None:
        super().__init__(flush_every=flush_every)
        self._output_dir = Path(output_dir)
        self._path = self._output_dir / _FILENAME
        self._conn: sqlite3.Connection | None = None
        self._run_id: str | None = None

    @property
    def path(self) -> Path:
        return self._path

    def open(self, run_id: str) -> None:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        existed = self._path.exists() and self._path.stat().st_size > 0
        try:
            self._conn = sqlite3.connect(self._path)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open sqlite at {self._path}: {exc}") from exc
        try:
            cur = self._conn.cursor()
            cur.execute(_CREATE_SQL)
            cur.execute(_CREATE_INDEX_SQL)
            self._conn.commit()
            if existed:
                # Sanity-проверка: если в файле уже есть записи с другим run_id,
                # запрещаем дописывать сюда — это чужой эксперимент.
                cur.execute(
                    "SELECT DISTINCT run_id FROM attempts WHERE run_id != ? LIMIT 1",
                    (run_id,),
                )
                row = cur.fetchone()
                if row is not None:
                    raise StorageError(
                        f"sqlite file {self._path} already contains run_id={row[0]!r}, "
                        f"refuses to mix with run_id={run_id!r}"
                    )
        except Exception:
            # При любой ошибке во время open() — закрываем коннект, чтобы не течь.
            self._conn.close()
            self._conn = None
            raise
        self._run_id = run_id
        self._opened = True

    def max_attempt_no(self, run_id: str) -> int | None:
        """Return max attempt_no for the given run_id, or None if no rows yet."""
        if self._conn is None:
            raise StorageError("SQLiteSink not open")
        cur = self._conn.cursor()
        cur.execute(
            "SELECT MAX(attempt_no) FROM attempts WHERE run_id = ?", (run_id,)
        )
        row = cur.fetchone()
        if row is None or row[0] is None:
            return None
        return int(row[0])

    def write(self, record: AttemptRecord) -> None:
        self._buffered_write(record)

    def _flush_records(self, records: list[AttemptRecord]) -> None:
        if self._conn is None:
            raise StorageError("SQLiteSink not open")
        rows = [_row(r) for r in records]
        try:
            self._conn.executemany(_INSERT_SQL, rows)
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError(f"sqlite write failed: {exc}") from exc

    def close(self) -> None:
        try:
            self._buffered_close()
        finally:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


def _row(record: AttemptRecord) -> tuple[Any, ...]:
    """Pack AttemptRecord into the column tuple expected by _INSERT_SQL."""
    ts_str = record.timestamp.isoformat()
    kind_str = record.attempt_kind.value
    return (
        ts_str,
        record.run_id,
        record.attempt_no,
        record.target_id,
        record.payload_id,
        record.payload_text,
        json.dumps(list(record.chromosome), ensure_ascii=False),
        record.mutated_request_summary,
        record.status_code,
        record.response_time_ms,
        1 if record.waf_blocked else 0,
        record.waf_signature_hit,
        1 if record.exploit_confirmed else 0,
        record.oracle_reason,
        1 if record.bypass else 0,
        record.ucb_reward,
        kind_str,
        record.seed,
    )


__all__ = ["SQLiteSink"]
