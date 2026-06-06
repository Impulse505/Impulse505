"""JSONLSink — JSON-Lines сток для AttemptRecord.

Файл: ``<output_dir>/attempts.jsonl``. Один JSON-объект на строку,
никаких массивных скобок, разделитель — ровно ``\\n``. Используется
``record.model_dump_json()`` (нативный сериализатор pydantic v2).
"""

from __future__ import annotations

from pathlib import Path
from typing import IO

from amhf.storage.schema import AttemptRecord
from amhf.storage.sink import BufferedSink, StorageError

_FILENAME = "attempts.jsonl"


class JSONLSink(BufferedSink):
    """Append-only JSONL-сток."""

    def __init__(self, output_dir: Path | str, *, flush_every: int = 1) -> None:
        super().__init__(flush_every=flush_every)
        self._output_dir = Path(output_dir)
        self._path = self._output_dir / _FILENAME
        self._fp: IO[str] | None = None
        self._run_id: str | None = None

    @property
    def path(self) -> Path:
        return self._path

    def open(self, run_id: str) -> None:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        # newline='' предотвращает преобразование \n -> \r\n на Windows.
        self._fp = self._path.open("a", encoding="utf-8", newline="")
        self._run_id = run_id
        self._opened = True

    def write(self, record: AttemptRecord) -> None:
        self._buffered_write(record)

    def _flush_records(self, records: list[AttemptRecord]) -> None:
        if self._fp is None:
            raise StorageError("JSONLSink not open")
        for r in records:
            line = r.model_dump_json()
            self._fp.write(line)
            self._fp.write("\n")
        self._fp.flush()

    def close(self) -> None:
        try:
            self._buffered_close()
        finally:
            if self._fp is not None:
                self._fp.close()
                self._fp = None


__all__ = ["JSONLSink"]
