"""Logging setup — human-readable stdout (rich) + JSON-lines file."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.logging import RichHandler


class JsonLineFormatter(logging.Formatter):
    """Formats log records as one JSON object per line (NDJSON)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # extra-поля, переданные через logger.info(..., extra={...}), сохраняем как есть.
        for key, value in record.__dict__.items():
            if key in _STD_RECORD_KEYS or key.startswith("_"):
                continue
            try:
                json.dumps(value)
            except (TypeError, ValueError):
                value = repr(value)
            payload[key] = value
        return json.dumps(payload, ensure_ascii=False)


_STD_RECORD_KEYS = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message", "taskName",
    }
)


def setup_logging(level: str = "INFO", json_file: Path | str | None = None) -> None:
    """Configure root logger with rich console handler and optional JSONL file.

    Idempotent: clears existing handlers before attaching new ones so that
    repeated calls (e.g. in tests) do not duplicate output.
    """
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())

    console = RichHandler(
        show_path=False,
        show_time=True,
        rich_tracebacks=True,
        markup=False,
    )
    console.setFormatter(logging.Formatter("%(message)s"))
    console.setLevel(level.upper())
    root.addHandler(console)

    if json_file is not None:
        path = Path(json_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(JsonLineFormatter())
        file_handler.setLevel(level.upper())
        root.addHandler(file_handler)

    # aiohttp/asyncio шумят на DEBUG — приглушаем по умолчанию.
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)


def banner(message: str) -> None:
    """Convenience: log a visually distinct banner at INFO level."""
    logging.getLogger("amhf").info("=== %s ===", message)


# Гарантируем, что библиотечные импорты до setup_logging() не валятся в stderr.
logging.getLogger("amhf").addHandler(logging.NullHandler())


__all__ = ["JsonLineFormatter", "banner", "setup_logging"]


# Приватный экспорт для тестов и type-checker'ов.
def _module_smoke() -> None:  # pragma: no cover
    sys.stderr.write("amhf.utils.logging loaded\n")
