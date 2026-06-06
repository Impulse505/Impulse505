"""Алгоритм UCB1 — multi-armed bandit над хромосомами.

Каждая хромосома считается «рукой» (arm). Приоритет:
priority(i) = mean_i + c * sqrt(2 * ln N / n_i),  n_i > 0
priority(i) = +inf,                               n_i = 0
где N — суммарное число розыгрышей по всем рукам. select_batch(k)
возвращает k лучших по приоритету БЕЗ внутрибатчевой переоценки —
«asynchronous batch UCB» под concurrency оркестратора.
"""

from __future__ import annotations

import math

from amhf.scheduler._ucb1_stats import ArmStats
from amhf.scheduler.chromosome import Chromosome


class UCB1Bandit:
    """UCB1 over chromosome arms with deterministic, stable tie-breaking."""

    def __init__(self, *, c: float = math.sqrt(2.0)) -> None:
        self._c: float = c
        self._arms: dict[Chromosome, ArmStats] = {}
        self._N: int = 0

    @property
    def total_pulls(self) -> int:
        return self._N

    def add_arm(self, arm: Chromosome) -> None:
        # Идемпотентно: повторный add не сбрасывает счётчики.
        self._arms.setdefault(arm, ArmStats(arm_id=arm))

    def remove_arm(self, arm: Chromosome) -> None:
        self._arms.pop(arm, None)

    def stats(self, arm: Chromosome) -> ArmStats:
        return self._arms[arm]

    def all_stats(self) -> list[ArmStats]:
        return list(self._arms.values())

    def priority(self, arm: Chromosome) -> float:
        s = self._arms[arm]
        if s.n == 0:
            return math.inf
        # Логарифм по суммарному N — общий счётчик розыгрышей.
        return s.mean + self._c * math.sqrt(2.0 * math.log(self._N) / s.n)

    def _ranked(self) -> list[Chromosome]:
        if not self._arms:
            raise RuntimeError("UCB1Bandit: no arms registered")
        # Стабильная сортировка: сначала -priority, затем сам tuple для tie-break.
        return sorted(
            self._arms.keys(),
            key=lambda a: (-self.priority(a), a),
        )

    def select_one(self) -> Chromosome:
        return self._ranked()[0]

    def select_batch(self, k: int) -> list[Chromosome]:
        if k <= 0:
            return []
        return self._ranked()[:k]

    def update(self, arm: Chromosome, reward: int) -> None:
        if arm not in self._arms:
            raise KeyError(f"UCB1Bandit.update: unknown arm {arm!r}")
        s = self._arms[arm]
        s.n += 1
        s.sum_reward += float(reward)
        self._N += 1
        s.last_played_at = self._N


__all__ = ["ArmStats", "UCB1Bandit"]
