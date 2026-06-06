"""TimingOracle — оракул задержки для time-based blind SQLi.

Поддерживает два режима:
  * **calibrated** — при наличии baseline-выборки latency считает
    ``threshold = mean + k*sigma`` и сравнивает elapsed_ms с порогом.
  * **fixed-threshold** — fallback, когда выборки недостаточно: используется
    статический порог в миллисекундах (``cfg.sqli.time_delay_threshold_ms``).
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class TimingOracle:
    """Time-based oracle: pure-data объект, без I/O."""

    baseline_mean_ms: float = 0.0
    baseline_stddev_ms: float = 0.0
    k: float = 3.0
    fixed_threshold_ms: float | None = None

    @classmethod
    def calibrated(
        cls,
        samples_ms: Sequence[float],
        k: float = 3.0,
        min_samples: int = 20,
    ) -> TimingOracle:
        """Build oracle from a baseline of latency samples (mean + k*sigma)."""
        if len(samples_ms) < min_samples:
            raise ValueError(
                f"calibrated() needs at least {min_samples} samples, "
                f"got {len(samples_ms)}"
            )
        mean = statistics.fmean(samples_ms)
        # pstdev — population stddev; для baseline это корректнее sample-stddev.
        stddev = statistics.pstdev(samples_ms)
        return cls(
            baseline_mean_ms=mean,
            baseline_stddev_ms=stddev,
            k=k,
            fixed_threshold_ms=None,
        )

    @classmethod
    def from_threshold(cls, threshold_ms: float) -> TimingOracle:
        """Build oracle with a fixed threshold (no calibration)."""
        if threshold_ms <= 0.0:
            raise ValueError(f"threshold_ms must be > 0, got {threshold_ms}")
        return cls(fixed_threshold_ms=threshold_ms)

    @property
    def threshold_ms(self) -> float:
        """Effective threshold used by ``is_delayed``."""
        if self.fixed_threshold_ms is not None:
            return self.fixed_threshold_ms
        return self.baseline_mean_ms + self.k * self.baseline_stddev_ms

    def is_delayed(self, elapsed_ms: float) -> bool:
        """True iff elapsed_ms strictly exceeds the configured threshold."""
        return elapsed_ms > self.threshold_ms
