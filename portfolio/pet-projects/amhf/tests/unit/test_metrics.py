"""Unit tests for amhf.metrics — pure functions over AttemptRecord lists."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from amhf.metrics import (
    bypass_rate,
    false_positive_rate,
    per_chromosome_stats,
    throughput,
    time_to_first_bypass,
)
from amhf.storage.schema import AttemptKind, AttemptRecord


def _record(
    *,
    attempt_no: int,
    bypass: bool,
    payload_id: str = "p",
    chromosome: list[str] | None = None,
    timestamp: datetime | None = None,
) -> AttemptRecord:
    return AttemptRecord(
        timestamp=timestamp or datetime.now(tz=UTC),
        run_id="run",
        attempt_no=attempt_no,
        target_id="t",
        payload_id=payload_id,
        payload_text="x",
        chromosome=chromosome or ["url_encode"],
        status_code=200,
        response_time_ms=1.0,
        waf_blocked=False,
        exploit_confirmed=bypass,
        bypass=bypass,
        ucb_reward=1 if bypass else 0,
        attempt_kind=AttemptKind.MUTATION,
        seed=42,
    )


def test_bypass_rate_3_of_10() -> None:
    rs = [_record(attempt_no=i, bypass=(i < 3)) for i in range(10)]
    assert bypass_rate(rs) == pytest.approx(0.3)


def test_bypass_rate_empty() -> None:
    assert bypass_rate([]) == 0.0


def test_time_to_first_bypass_returns_attempt_no() -> None:
    rs = [
        _record(attempt_no=0, bypass=False),
        _record(attempt_no=1, bypass=False),
        _record(attempt_no=2, bypass=True),
        _record(attempt_no=3, bypass=True),
    ]
    assert time_to_first_bypass(rs) == 2


def test_time_to_first_bypass_none_when_no_bypass() -> None:
    rs = [_record(attempt_no=i, bypass=False) for i in range(5)]
    assert time_to_first_bypass(rs) is None


def test_throughput_positive() -> None:
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    rs = [
        _record(attempt_no=i, bypass=False, timestamp=t0 + timedelta(seconds=i))
        for i in range(11)
    ]
    # 11 records spanning 10s -> 1.1 attempts/s
    assert throughput(rs) == pytest.approx(1.1, rel=0.01)


def test_throughput_zero_for_single_record() -> None:
    rs = [_record(attempt_no=0, bypass=False)]
    assert throughput(rs) == 0.0


def test_throughput_zero_for_empty() -> None:
    assert throughput([]) == 0.0


def test_throughput_zero_for_zero_span() -> None:
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    rs = [_record(attempt_no=i, bypass=False, timestamp=t0) for i in range(3)]
    assert throughput(rs) == 0.0


def test_false_positive_rate_default_no_groundtruth() -> None:
    """Без confirmed_baseline_ids возвращает 0.0."""
    rs = [_record(attempt_no=i, bypass=True) for i in range(3)]
    assert false_positive_rate(rs) == 0.0


def test_false_positive_rate_with_groundtruth() -> None:
    rs = [
        _record(attempt_no=0, bypass=True, payload_id="known"),
        _record(attempt_no=1, bypass=True, payload_id="unknown"),
        _record(attempt_no=2, bypass=False, payload_id="anything"),
    ]
    rate = false_positive_rate(rs, confirmed_baseline_ids=["known"])
    # 1 of 2 bypass records is "unknown" -> FPR = 0.5
    assert rate == pytest.approx(0.5)


def test_false_positive_rate_no_bypass_records_returns_zero() -> None:
    rs = [_record(attempt_no=0, bypass=False)]
    assert false_positive_rate(rs, confirmed_baseline_ids=["x"]) == 0.0


def test_per_chromosome_stats_aggregates() -> None:
    rs = [
        _record(attempt_no=0, bypass=True, chromosome=["a"]),
        _record(attempt_no=1, bypass=False, chromosome=["a"]),
        _record(attempt_no=2, bypass=True, chromosome=["b"]),
        _record(attempt_no=3, bypass=True, chromosome=["b"]),
        _record(attempt_no=4, bypass=False, chromosome=["b"]),
    ]
    stats = per_chromosome_stats(rs)
    by_key = {s["chromosome"]: s for s in stats}
    assert by_key["a"]["n"] == 2
    assert by_key["a"]["bypass_rate"] == pytest.approx(0.5)
    assert by_key["b"]["n"] == 3
    assert by_key["b"]["bypass_rate"] == pytest.approx(2 / 3)
    # Sorted by n descending then by chromosome string.
    assert stats[0]["chromosome"] == "b"


def test_per_chromosome_stats_empty() -> None:
    assert per_chromosome_stats([]) == []
