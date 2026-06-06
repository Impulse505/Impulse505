"""Pure metric functions over Iterable[AttemptRecord].

Все функции — чистые, без I/O. Принимают Iterable, материализуют один раз
и возвращают число / список / None.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from amhf.storage.schema import AttemptRecord


def bypass_rate(records: Iterable[AttemptRecord]) -> float:
    """Доля записей с ``bypass=True`` (0.0..1.0; 0.0 если записей нет)."""
    rs = list(records)
    if not rs:
        return 0.0
    n_bypass = sum(1 for r in rs if r.bypass)
    return n_bypass / len(rs)


def time_to_first_bypass(records: Iterable[AttemptRecord]) -> int | None:
    """``attempt_no`` первой успешной попытки (или None если bypass не было).

    Здесь возвращается именно ``attempt_no`` записи, а не индекс в списке —
    оркестратор пишет attempt_no в порядке выполнения, и это инвариантно
    к фильтрации входной последовательности.
    """
    for r in records:
        if r.bypass:
            return int(r.attempt_no)
    return None


def throughput(records: Iterable[AttemptRecord]) -> float:
    """Попыток в секунду от min до max timestamp; 0.0 если < 2 записей."""
    rs = list(records)
    if len(rs) < 2:
        return 0.0
    timestamps = [r.timestamp for r in rs]
    span = (max(timestamps) - min(timestamps)).total_seconds()
    if span <= 0.0:
        return 0.0
    return len(rs) / span


def false_positive_rate(
    records: Iterable[AttemptRecord],
    *,
    confirmed_baseline_ids: Sequence[str] = (),
) -> float:
    """Доля «ложных» bypass'ов: bypass=True, но payload_id не в списке подтверждённых.

    Без ``confirmed_baseline_ids`` оценить FP без ground-truth невозможно —
    функция возвращает 0.0 (а не NaN) для удобства агрегации.
    """
    if not confirmed_baseline_ids:
        return 0.0
    confirmed = frozenset(confirmed_baseline_ids)
    rs = [r for r in records if r.bypass]
    if not rs:
        return 0.0
    n_fp = sum(1 for r in rs if r.payload_id not in confirmed)
    return n_fp / len(rs)


def per_chromosome_stats(records: Iterable[AttemptRecord]) -> list[dict[str, Any]]:
    """Группировка по хромосоме: ``[{chromosome, n, bypass_rate}, ...]``.

    Хромосома сериализуется как строка через ``", ".join(genes)`` — это
    устойчиво и в выводе CSV/JSON даёт читаемый ключ.
    """
    grouped: dict[str, dict[str, int]] = {}
    for r in records:
        key = ",".join(r.chromosome)
        bucket = grouped.setdefault(key, {"n": 0, "bypass": 0})
        bucket["n"] += 1
        if r.bypass:
            bucket["bypass"] += 1
    out: list[dict[str, Any]] = []
    for chrom, bucket in grouped.items():
        n = bucket["n"]
        out.append(
            {
                "chromosome": chrom,
                "n": n,
                "bypass_rate": (bucket["bypass"] / n) if n > 0 else 0.0,
            }
        )
    # Стабильный порядок: по убыванию n, затем по строке хромосомы.
    out.sort(key=lambda d: (-int(d["n"]), str(d["chromosome"])))
    return out


__all__ = [
    "bypass_rate",
    "false_positive_rate",
    "per_chromosome_stats",
    "throughput",
    "time_to_first_bypass",
]
