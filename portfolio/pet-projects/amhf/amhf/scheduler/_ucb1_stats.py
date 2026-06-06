"""Вспомогательная структура UCB1: ArmStats (выделена из ucb1.py для компактности)."""

from __future__ import annotations

from dataclasses import dataclass

from amhf.scheduler.chromosome import Chromosome


@dataclass(slots=True)
class ArmStats:
    """Per-arm UCB1 statistics: pulls, sum of rewards, last play step."""

    arm_id: Chromosome
    n: int = 0
    sum_reward: float = 0.0
    last_played_at: int = -1

    @property
    def mean(self) -> float:
        """Average reward; 0.0 if the arm was never played."""
        return self.sum_reward / self.n if self.n > 0 else 0.0
