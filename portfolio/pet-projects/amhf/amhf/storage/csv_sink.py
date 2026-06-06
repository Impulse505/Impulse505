"""CSVSink — RFC 4180 CSV writer для AttemptRecord.

Файл: ``<output_dir>/attempts.csv``. UTF-8, заголовок один раз.
``chromosome`` сериализуется как JSON-строка, остальные поля приводятся
к строке стандартными правилами csv.writer.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import IO, Any

from amhf.storage.schema import AttemptRecord
from amhf.storage.sink import BufferedSink, StorageError

_FILENAME = "attempts.csv"

# Порядок колонок в CSV — фиксированный, совпадает с порядком model_fields.
_FIELDS: list[str] = list(AttemptRecord.model_fields.keys())


class CSVSink(BufferedSink):
    """RFC-4180 CSV-сток для AttemptRecord."""

    def __init__(self, output_dir: Path | str, *, flush_every: int = 1) -> None:
        super().__init__(flush_every=flush_every)
        self._output_dir = Path(output_dir)
        self._path = self._output_dir / _FILENAME
        self._fp: IO[str] | None = None
        self._writer: Any = None
        self._run_id: str | None = None

    @property
    def path(self) -> Path:
        return self._path

    def open(self, run_id: str) -> None:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        write_header = not self._path.exists() or self._path.stat().st_size == 0
        # newline='' — обязательная мера для csv-модуля на Windows.
        self._fp = self._path.open("a", encoding="utf-8", newline="")
        self._writer = csv.writer(self._fp, quoting=csv.QUOTE_MINIMAL)
        if write_header:
            self._writer.writerow(_FIELDS)
        self._run_id = run_id
        self._opened = True

    def write(self, record: AttemptRecord) -> None:
        self._buffered_write(record)

    def _flush_records(self, records: list[AttemptRecord]) -> None:
        if self._fp is None or self._writer is None:
            raise StorageError("CSVSink not open")
        for r in records:
            self._writer.writerow(_row(r))
        self._fp.flush()

    def close(self) -> None:
        try:
            self._buffered_close()
        finally:
            if self._fp is not None:
                self._fp.close()
                self._fp = None
                self._writer = None


def _row(record: AttemptRecord) -> list[str]:
    """Convert one AttemptRecord into a list of cell strings."""
    out: list[str] = []
    for name in _FIELDS:
        value: Any = getattr(record, name)
        if name == "chromosome":
            out.append(json.dumps(list(value), ensure_ascii=False))
        elif name == "timestamp":
            # ISO-8601, naive-friendly — pydantic timestamp is timezone-aware.
            out.append(record.timestamp.isoformat())
        elif name == "attempt_kind":
            out.append(record.attempt_kind.value)
        elif value is None:
            out.append("")
        elif isinstance(value, bool):
            out.append("true" if value else "false")
        else:
            out.append(str(value))
    return out


__all__ = ["CSVSink"]
