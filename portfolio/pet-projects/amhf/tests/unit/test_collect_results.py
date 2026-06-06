"""Unit tests for the multi-seed aggregator helpers in scripts/collect_results.

Tests for the multi-seed aggregator: Wilson 95% confidence interval, per-seed
rates extraction, and the pooled summary used for the multi-seed CSV.
"""

from __future__ import annotations

import math

import pandas as pd
import pytest

from scripts.collect_results import (
    per_seed_rates,
    pooled_summary,
    wilson_ci,
)

# --------------------------------------------------------------------------- #
# wilson_ci                                                                    #
# --------------------------------------------------------------------------- #


def test_wilson_ci_n_zero_returns_full_range() -> None:
    lo, hi = wilson_ci(0, 0)
    assert lo == 0.0
    assert hi == 1.0


def test_wilson_ci_known_values() -> None:
    # Reference: Wilson 1927 — for k=0/n=10 at z=1.96 the interval is
    # roughly (0.0, 0.278). Tolerance ±0.005.
    lo, hi = wilson_ci(0, 10)
    assert lo == pytest.approx(0.0, abs=1e-9)
    assert hi == pytest.approx(0.278, abs=0.01)
    # k=5/n=10 → centered around 0.5, half-width about 0.30.
    lo, hi = wilson_ci(5, 10)
    assert lo == pytest.approx(0.237, abs=0.01)
    assert hi == pytest.approx(0.763, abs=0.01)


def test_wilson_ci_clamped_to_unit_interval() -> None:
    # n=1, k=1 → the upper bound never exceeds 1.0.
    lo, hi = wilson_ci(1, 1)
    assert 0.0 <= lo <= 1.0
    assert 0.0 <= hi <= 1.0


def test_wilson_ci_symmetric_around_p_hat_for_large_n() -> None:
    # For n large, Wilson CI ≈ Wald CI (symmetric ±1.96·σ̂).
    n, k = 10000, 5000
    lo, hi = wilson_ci(k, n)
    p_hat = k / n
    halfwidth_lo = p_hat - lo
    halfwidth_hi = hi - p_hat
    assert math.isclose(halfwidth_lo, halfwidth_hi, abs_tol=1e-3)
    assert halfwidth_lo == pytest.approx(0.0098, abs=0.005)


# --------------------------------------------------------------------------- #
# per_seed_rates / pooled_summary                                              #
# --------------------------------------------------------------------------- #


def _make_attempts(rows: list[dict[str, object]]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def test_per_seed_rates_groups_by_seed() -> None:
    df = _make_attempts([
        {"scenario": "s4", "waf": "modsec_p1", "seed": 42, "bypass": True},
        {"scenario": "s4", "waf": "modsec_p1", "seed": 42, "bypass": False},
        {"scenario": "s4", "waf": "modsec_p1", "seed": 137, "bypass": False},
        {"scenario": "s4", "waf": "modsec_p1", "seed": 137, "bypass": False},
    ])
    out = per_seed_rates(df, success_col="bypass")
    assert len(out) == 2  # two seeds
    seed_42 = out[out["seed"] == 42].iloc[0]
    seed_137 = out[out["seed"] == 137].iloc[0]
    assert seed_42["rate"] == 0.5
    assert seed_137["rate"] == 0.0
    assert int(seed_42["n"]) == 2
    assert int(seed_42["successes"]) == 1


def test_per_seed_rates_empty_input() -> None:
    out = per_seed_rates(pd.DataFrame(), success_col="bypass")
    assert out.empty


def test_pooled_summary_combines_seeds_with_wilson_ci() -> None:
    # Three seeds, identical 1-of-10 success rate, all on same (sce, waf).
    rows: list[dict[str, object]] = []
    for seed in (42, 137, 256):
        rows.append({"scenario": "s4", "waf": "naxsi", "seed": seed, "bypass": True})
        for _ in range(9):
            rows.append({
                "scenario": "s4", "waf": "naxsi", "seed": seed, "bypass": False,
            })
    df = _make_attempts(rows)
    out = pooled_summary(df, success_col="bypass")
    assert len(out) == 1
    row = out.iloc[0]
    assert int(row["n_seeds"]) == 3
    assert int(row["n_attempts_total"]) == 30
    assert int(row["successes_total"]) == 3
    assert row["rate_pooled"] == pytest.approx(0.1, abs=1e-12)
    # All seeds had identical rate → std is zero.
    assert row["rate_std_per_seed"] == pytest.approx(0.0, abs=1e-12)
    assert row["rate_mean_per_seed"] == pytest.approx(0.1, abs=1e-12)
    # Wilson CI around 3/30 → roughly (0.034, 0.260) at z=1.96.
    assert 0.0 < float(row["ci95_lo"]) < 0.05
    assert 0.20 < float(row["ci95_hi"]) < 0.30


def test_pooled_summary_diverging_seeds_have_nonzero_std() -> None:
    rows: list[dict[str, object]] = []
    # Seed 42: 0/10. Seed 137: 5/10. Seed 256: 10/10. Std should be ≈ 0.5.
    seed_to_successes = {42: 0, 137: 5, 256: 10}
    for seed, k in seed_to_successes.items():
        for i in range(10):
            rows.append({
                "scenario": "s2", "waf": "modsec_p1", "seed": seed,
                "bypass": i < k,
            })
    df = _make_attempts(rows)
    out = pooled_summary(df, success_col="bypass")
    assert len(out) == 1
    row = out.iloc[0]
    assert int(row["n_seeds"]) == 3
    # Per-seed rates are 0.0, 0.5, 1.0 → mean 0.5, sample std = 0.5.
    assert row["rate_mean_per_seed"] == pytest.approx(0.5, abs=1e-9)
    assert row["rate_std_per_seed"] == pytest.approx(0.5, abs=1e-9)


def test_pooled_summary_alternative_success_column() -> None:
    # Verify the function works for waf_blocked too (used in FPR + block charts).
    df = _make_attempts([
        {"scenario": "fpr", "waf": "naxsi", "seed": 42, "waf_blocked": True},
        {"scenario": "fpr", "waf": "naxsi", "seed": 42, "waf_blocked": False},
        {"scenario": "fpr", "waf": "naxsi", "seed": 137, "waf_blocked": True},
        {"scenario": "fpr", "waf": "naxsi", "seed": 137, "waf_blocked": True},
    ])
    out = pooled_summary(df, group_cols=("waf",), success_col="waf_blocked")
    assert len(out) == 1
    row = out.iloc[0]
    assert int(row["successes_total"]) == 3
    assert int(row["n_attempts_total"]) == 4
    assert row["rate_pooled"] == pytest.approx(0.75, abs=1e-12)
