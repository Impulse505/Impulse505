"""Storage subsystem — sinks (CSV, SQLite, JSONL) и AttemptRecord."""

from __future__ import annotations

from amhf.storage.csv_sink import CSVSink
from amhf.storage.jsonl_sink import JSONLSink
from amhf.storage.schema import AttemptKind, AttemptRecord
from amhf.storage.sink import Sink, StorageError
from amhf.storage.sqlite_sink import SQLiteSink

__all__ = [
    "AttemptKind",
    "AttemptRecord",
    "CSVSink",
    "JSONLSink",
    "SQLiteSink",
    "Sink",
    "StorageError",
]
