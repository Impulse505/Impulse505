"""Corpus loader — pydantic-валидация YAML-файлов с payload'ами.

Каждый файл ``corpus/<class>.yaml`` — список словарей с фиксированной
схемой (см. ``CorpusEntry``). На Stage 1–4 используются 5–10 заглушек на
класс; на Stage 5+ те же файлы заменяются полным набором (264 entries),
без правок кода.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import numpy as np
import yaml
from pydantic import BaseModel, ConfigDict, Field

AttackClass = Literal["sqli", "xss", "cmdi", "pathtrav"]


class CorpusEntry(BaseModel):
    """Одна запись corpus — иммутабельная, schema-strict."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )

    id: str
    cls: AttackClass = Field(alias="class", validation_alias="class")
    payload: str
    description: str = ""
    expected_markers: list[str] = Field(default_factory=list)
    difficulty: Literal["trivial", "easy", "medium", "hard"] = "easy"
    source: str = ""


class Corpus:
    """In-memory набор CorpusEntry с детерминированной выборкой."""

    def __init__(self, entries: Sequence[CorpusEntry]) -> None:
        if not entries:
            raise ValueError("Corpus must contain at least one entry")
        self._entries: tuple[CorpusEntry, ...] = tuple(entries)
        # Индекс по классу — для быстрого by_class и фильтрации в sample.
        self._by_class: dict[str, list[CorpusEntry]] = {}
        for entry in self._entries:
            self._by_class.setdefault(entry.cls, []).append(entry)

    @classmethod
    def from_yaml_paths(
        cls,
        paths: Sequence[Path],
        *,
        filter_class: str | None = None,
        max_payloads: int | None = None,
    ) -> Corpus:
        """Загрузить и валидировать YAML-файлы; опц. фильтр и лимит."""
        loaded: list[CorpusEntry] = []
        for raw_path in paths:
            path = Path(raw_path)
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, list):
                raise ValueError(
                    f"Corpus file {path} must be a YAML list, got {type(data).__name__}"
                )
            for raw in data:
                # populate_by_name + validation_alias='class' позволяют
                # YAML-ключу 'class:' нормально попадать в поле .cls.
                entry = CorpusEntry.model_validate(raw)
                if filter_class is not None and entry.cls != filter_class:
                    continue
                loaded.append(entry)
        if max_payloads is not None and max_payloads > 0:
            loaded = loaded[:max_payloads]
        if not loaded:
            raise ValueError(
                f"No corpus entries loaded from {[str(p) for p in paths]} "
                f"(filter_class={filter_class!r})"
            )
        return cls(loaded)

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> tuple[CorpusEntry, ...]:
        return self._entries

    def by_class(self, cls: str) -> list[CorpusEntry]:
        """Все записи указанного класса (копия списка)."""
        return list(self._by_class.get(cls, ()))

    def classes(self) -> list[str]:
        """Список классов, представленных в корпусе."""
        return list(self._by_class.keys())

    def sample(self, rng: np.random.Generator) -> CorpusEntry:
        """Случайно выбрать одну запись (равновероятно)."""
        idx = int(rng.integers(0, len(self._entries)))
        return self._entries[idx]

    def sample_class(self, cls: str, rng: np.random.Generator) -> CorpusEntry:
        """Случайная запись указанного класса."""
        bucket = self._by_class.get(cls)
        if not bucket:
            raise KeyError(f"Corpus has no entries for class {cls!r}")
        idx = int(rng.integers(0, len(bucket)))
        return bucket[idx]


__all__ = ["AttackClass", "Corpus", "CorpusEntry"]
