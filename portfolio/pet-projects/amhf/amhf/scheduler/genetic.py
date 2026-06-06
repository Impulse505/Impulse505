"""Генетический алгоритм над хромосомами.

Топ-k родителей по среднему вознаграждению; однотoчечный кроссовер;
мутация replace/insert/delete; репэйр отбрасывает несовместимые гены.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

from amhf.mutators.base import MutatorId
from amhf.scheduler._ga_helpers import (
    crossover_one_point,
    default_alphabet,
    mutate_chromosome,
    repair_chromosome,
    select_top_k,
)
from amhf.scheduler._ucb1_stats import ArmStats
from amhf.scheduler.chromosome import MAX_CHROMOSOME_LENGTH, Chromosome


class GeneticOperator:
    """One-point crossover + per-gene mutation + same-layer/excludes repair."""

    def __init__(
        self, *, p_replace: float, p_insert: float, p_delete: float,
        max_length: int = MAX_CHROMOSOME_LENGTH,
        alphabet: Sequence[MutatorId] | None = None,
    ) -> None:
        self.p_replace, self.p_insert, self.p_delete = p_replace, p_insert, p_delete
        self.max_length = max_length
        self.alphabet: tuple[MutatorId, ...] = (
            tuple(alphabet) if alphabet is not None else default_alphabet()
        )

    def select_top_k(
        self, stats: Sequence[ArmStats], k: int, *, min_plays: int
    ) -> list[Chromosome]:
        return select_top_k(stats, k, min_plays=min_plays)

    def crossover(
        self, p1: Chromosome, p2: Chromosome, rng: np.random.Generator
    ) -> Chromosome:
        return crossover_one_point(p1, p2, rng)

    def mutate(self, chrom: Chromosome, rng: np.random.Generator) -> Chromosome:
        return mutate_chromosome(
            chrom, rng, p_replace=self.p_replace, p_insert=self.p_insert,
            p_delete=self.p_delete, alphabet=self.alphabet, max_length=self.max_length,
        )

    def repair(self, chrom: Chromosome) -> Chromosome | None:
        return repair_chromosome(chrom, max_length=self.max_length)

    def evolve(
        self, stats: Sequence[ArmStats], *,
        k: int, min_plays: int, offspring_per_round: int,
        rng: np.random.Generator,
    ) -> list[Chromosome]:
        parents = self.select_top_k(stats, k, min_plays=min_plays)
        if len(parents) < 2:
            return []
        seen: set[Chromosome] = set(parents)
        offspring: list[Chromosome] = []
        for _ in range(offspring_per_round):
            i, j = rng.integers(0, len(parents), size=2)
            child = self.crossover(parents[int(i)], parents[int(j)], rng)
            child = self.mutate(child, rng)
            repaired = self.repair(child)
            if repaired is None or repaired in seen:
                continue
            seen.add(repaired)
            offspring.append(repaired)
        return offspring


__all__ = ["GeneticOperator"]
