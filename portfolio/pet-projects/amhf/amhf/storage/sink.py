"""Sink protocol — общий интерфейс для CSV/SQLite/JSONL стоков.

BufferedSink — миксин, реализующий буферизацию ``flush_every`` записей,
которую можно унаследовать конкретным стоком.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from amhf.storage.schema import AttemptRecord


class StorageError(Exception):
    """Raised when a sink cannot persist a record (corrupt file, mismatched run, etc.)."""


@runtime_checkable
class Sink(Protocol):
    """Persistent destination for AttemptRecord rows."""

    def open(self, run_id: str) -> None:
        """Prepare the underlying resource for the given run."""

    def write(self, record: AttemptRecord) -> None:
        """Append one record (may be buffered until ``flush()``)."""

    def flush(self) -> None:
        """Force pending buffered writes to durable storage."""

    def close(self) -> None:
        """Flush and release the underlying resource."""


class BufferedSink:
    """Mixin: collects records in a list and flushes every ``flush_every``.

    Subclasses must implement ``_flush_records(records)`` doing the
    actual I/O, and call ``self._buffered_write(record)`` from their
    ``write()`` and ``self._buffered_close()`` from ``close()``.
    """

    def __init__(self, flush_every: int = 1) -> None:
        if flush_every <= 0:
            raise ValueError("flush_every must be > 0")
        self._flush_every = flush_every
        self._buffer: list[AttemptRecord] = []
        self._opened = False

    def _buffered_write(self, record: AttemptRecord) -> None:
        if not self._opened:
            raise StorageError("sink.write() called before sink.open()")
        self._buffer.append(record)
        if len(self._buffer) >= self._flush_every:
            self._do_flush()

    def _do_flush(self) -> None:
        if not self._buffer:
            return
        records = self._buffer
        self._buffer = []
        self._flush_records(records)

    def _flush_records(self, records: list[AttemptRecord]) -> None:  # pragma: no cover
        raise NotImplementedError

    def flush(self) -> None:
        self._do_flush()

    def _buffered_close(self) -> None:
        self._do_flush()
        self._opened = False


__all__ = ["BufferedSink", "Sink", "StorageError"]
