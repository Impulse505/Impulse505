"""Unit tests for TimingOracle (Stage 3)."""

from __future__ import annotations

import statistics

import pytest

from amhf.oracle.timing_oracle import TimingOracle


def test_calibrated_threshold_and_is_delayed() -> None:
    """20-sample baseline; verify exact threshold and is_delayed boundary."""
    samples = [100.0, 110.0, 95.0, 105.0, 100.0] * 4  # 20 samples
    assert len(samples) == 20
    expected_mean = statistics.fmean(samples)
    expected_stddev = statistics.pstdev(samples)
    expected_threshold = expected_mean + 3.0 * expected_stddev

    oracle = TimingOracle.calibrated(samples, k=3.0)
    assert oracle.baseline_mean_ms == pytest.approx(expected_mean)
    assert oracle.baseline_stddev_ms == pytest.approx(expected_stddev)
    assert oracle.threshold_ms == pytest.approx(expected_threshold)

    # Strictly above threshold → delayed.
    assert oracle.is_delayed(expected_threshold + 0.1) is True
    # At-threshold (not strictly greater) → not delayed.
    assert oracle.is_delayed(expected_threshold) is False
    # Well below threshold → not delayed.
    assert oracle.is_delayed(50.0) is False


def test_calibrated_with_low_k_more_sensitive() -> None:
    """Lower k => lower threshold => 120ms can be delayed at small k."""
    samples = [100.0, 110.0, 95.0, 105.0, 100.0] * 4
    mean = statistics.fmean(samples)
    stddev = statistics.pstdev(samples)
    # Pick k such that mean + k*stddev < 120 < mean + 3*stddev.
    k_low = 1.0
    threshold_low = mean + k_low * stddev
    assert threshold_low < 120.0  # sanity
    oracle_low = TimingOracle.calibrated(samples, k=k_low)
    assert oracle_low.is_delayed(120.0) is (threshold_low < 120.0)


def test_fixed_threshold_mode() -> None:
    oracle = TimingOracle.from_threshold(2000.0)
    assert oracle.threshold_ms == 2000.0
    assert oracle.is_delayed(2500.0) is True
    assert oracle.is_delayed(1500.0) is False
    # Boundary check.
    assert oracle.is_delayed(2000.0) is False


def test_calibrated_short_baseline_raises() -> None:
    with pytest.raises(ValueError, match="at least"):
        TimingOracle.calibrated([100.0, 110.0, 95.0, 105.0])  # 4 samples


def test_calibrated_custom_min_samples() -> None:
    """Allow small baselines when caller relaxes min_samples (e.g. tests)."""
    samples = [100.0, 110.0, 95.0, 105.0, 100.0]  # 5 samples
    oracle = TimingOracle.calibrated(samples, k=2.0, min_samples=5)
    assert oracle.baseline_mean_ms == pytest.approx(102.0)


def test_from_threshold_rejects_zero_or_negative() -> None:
    with pytest.raises(ValueError):
        TimingOracle.from_threshold(0.0)
    with pytest.raises(ValueError):
        TimingOracle.from_threshold(-1.0)
