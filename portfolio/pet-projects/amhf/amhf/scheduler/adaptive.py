"""AdaptiveScheduler — UCB1 + GA-обновление пула хромосом.

Concurrency contract: ``next_batch(k)`` возвращает k хромосом по текущему
приоритету UCB1 без внутрибатчевой переоценки ("asynchronous batch UCB").
Награды приходят пакетом через ``report_rewards``; GA-эпоха стартует
автоматически, когда суммарный счётчик ``step`` пересекает кратное
``cfg.ga.period``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np

from amhf.config import SchedulerConfig
from amhf.mutators.base import Layer, MutatorId, RegistryOfMutators
from amhf.scheduler.chromosome import Chromosome
from amhf.scheduler.genetic import GeneticOperator
from amhf.scheduler.ucb1 import UCB1Bandit

# Порог отбраковки холодных рук в evolve_pool.
_CULL_REWARD_THRESHOLD: float = 0.05


class AdaptiveScheduler:
    """UCB1 over chromosomes plus periodic GA refresh of the pool."""

    def __init__(
        self,
        cfg: SchedulerConfig,
        *,
        mutator_ids: Sequence[MutatorId],
        rng: np.random.Generator,
    ) -> None:
        self._cfg = cfg
        self._rng = rng
        self._step = 0
        self.bandit = UCB1Bandit(c=cfg.ucb_c)
        self.ga = GeneticOperator(
            p_replace=cfg.ga.p_replace,
            p_insert=cfg.ga.p_insert,
            p_delete=cfg.ga.p_delete,
            max_length=cfg.max_chromosome_length,
            alphabet=mutator_ids,
        )
        self._mutator_ids = tuple(mutator_ids)
        # Группируем по слою для безопасной первичной генерации.
        self._by_layer: dict[Layer, list[MutatorId]] = {ly: [] for ly in Layer}
        for mid in self._mutator_ids:
            try:
                self._by_layer[RegistryOfMutators.by_id(mid).layer].append(mid)
            except KeyError:
                continue
        self._build_initial_pool()

    @property
    def pool_size(self) -> int:
        return len(self.bandit.all_stats())

    @property
    def step(self) -> int:
        return self._step

    # ------------------------------------------------------------------ #
    # Initial pool                                                       #
    # ------------------------------------------------------------------ #
    def _build_initial_pool(self) -> None:
        target = self._cfg.initial_pool_size
        # Слои, в которых вообще есть зарегистрированные мутаторы.
        non_empty_layers = [ly for ly in Layer if self._by_layer[ly]]
        if not non_empty_layers:
            raise RuntimeError("AdaptiveScheduler: no mutator ids available")
        max_len = min(3, len(non_empty_layers))
        pool: set[Chromosome] = set()
        attempts = 0
        max_attempts = target * 50
        while len(pool) < target and attempts < max_attempts:
            attempts += 1
            length = int(self._rng.integers(1, max(2, max_len + 1)))
            length = max(1, min(length, len(non_empty_layers)))
            layer_idxs = self._rng.choice(
                len(non_empty_layers), size=length, replace=False
            )
            chosen_layers = sorted(
                (non_empty_layers[int(i)] for i in layer_idxs),
                key=list(Layer).index,
            )
            genes: list[MutatorId] = []
            for ly in chosen_layers:
                bucket = self._by_layer[ly]
                genes.append(bucket[int(self._rng.integers(0, len(bucket)))])
            chrom: Chromosome = tuple(genes)
            pool.add(chrom)
        # Если до 50*target попыток не добили, добиваем дубликатами через arm_idem.
        for c in pool:
            self.bandit.add_arm(c)

    # ------------------------------------------------------------------ #
    # Selection / feedback                                                #
    # ------------------------------------------------------------------ #
    def next_batch(self, k: int) -> list[Chromosome]:
        if k <= 0:
            return []
        return self.bandit.select_batch(min(k, self.pool_size))

    def report_reward(self, chrom: Chromosome, reward: int) -> None:
        self.report_rewards([(chrom, reward)])

    def report_rewards(self, pairs: Sequence[tuple[Chromosome, int]]) -> None:
        if not pairs:
            return
        prev_step = self._step
        for arm, reward in pairs:
            self.bandit.update(arm, reward)
        self._step += len(pairs)
        period = self._cfg.ga.period
        if self._step // period > prev_step // period:
            self.evolve_pool()

    # ------------------------------------------------------------------ #
    # GA epoch                                                            #
    # ------------------------------------------------------------------ #
    def evolve_pool(self) -> list[Chromosome]:
        offspring = self.ga.evolve(
            self.bandit.all_stats(),
            k=self._cfg.ga.top_k,
            min_plays=self._cfg.ga.min_plays_for_selection,
            offspring_per_round=self._cfg.ga.offspring_per_round,
            rng=self._rng,
        )
        for child in offspring:
            self.bandit.add_arm(child)
        # Гистерезисный cull: если пул раздулся в 2 раза — режем «холодные» руки
        # с n>=min_plays и mean<_CULL_REWARD_THRESHOLD до возврата к initial_pool_size.
        cap = 2 * self._cfg.initial_pool_size
        if self.pool_size > cap:
            cold = [
                s for s in self.bandit.all_stats()
                if s.n >= self._cfg.ga.min_plays_for_selection
                and s.mean < _CULL_REWARD_THRESHOLD
            ]
            cold.sort(key=lambda s: (s.mean, -s.n))
            target = self._cfg.initial_pool_size
            for s in cold:
                if self.pool_size <= target:
                    break
                self.bandit.remove_arm(s.arm_id)
        return offspring

    # ------------------------------------------------------------------ #
    # Resume support                                                      #
    # ------------------------------------------------------------------ #
    def export_state(self) -> dict[str, Any]:
        return {
            "step": self._step,
            "arms": [
                {
                    "arm": list(s.arm_id),
                    "n": s.n,
                    "sum_reward": s.sum_reward,
                    "last_played_at": s.last_played_at,
                }
                for s in self.bandit.all_stats()
            ],
        }

    def import_state(self, state: dict[str, Any]) -> None:
        self._step = int(state["step"])
        # Полностью пересобираем бандит — иначе можно унаследовать «лишние» руки.
        new = UCB1Bandit(c=self._cfg.ucb_c)
        total = 0
        for entry in state["arms"]:
            arm: Chromosome = tuple(entry["arm"])
            new.add_arm(arm)
            stats = new.stats(arm)
            stats.n = int(entry["n"])
            stats.sum_reward = float(entry["sum_reward"])
            stats.last_played_at = int(entry["last_played_at"])
            total += stats.n
        new._N = total
        self.bandit = new


__all__ = ["AdaptiveScheduler"]
