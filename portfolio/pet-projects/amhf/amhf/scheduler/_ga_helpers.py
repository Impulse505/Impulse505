"""Вспомогательные функции для GeneticOperator (выделено из genetic.py)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import numpy as np

from amhf.mutators.base import MutatorId, RegistryOfMutators
from amhf.scheduler.chromosome import MAX_CHROMOSOME_LENGTH, Chromosome

if TYPE_CHECKING:
    from amhf.scheduler._ucb1_stats import ArmStats


def default_alphabet() -> tuple[MutatorId, ...]:
    """Returns the full registered MutatorId set as a stable tuple."""
    return tuple(sorted(RegistryOfMutators.all_ids()))  # type: ignore[arg-type]


def select_top_k(
    stats: Sequence[ArmStats], k: int, *, min_plays: int
) -> list[Chromosome]:
    """Filter arms with n>=min_plays, sort by mean desc (then by n desc), take k."""
    eligible = [s for s in stats if s.n >= min_plays]
    # Сортируем по убыванию mean, при равенстве — по убыванию n; tie-break по tuple.
    eligible.sort(key=lambda s: (-s.mean, -s.n, s.arm_id))
    return [s.arm_id for s in eligible[:k]]


def crossover_one_point(
    p1: Chromosome, p2: Chromosome, rng: np.random.Generator
) -> Chromosome:
    """One-point crossover; cut uniformly in range(1, min(len(p1), len(p2)))."""
    if min(len(p1), len(p2)) <= 1:
        return p1
    cut = int(rng.integers(1, min(len(p1), len(p2))))
    child = p1[:cut] + p2[cut:]
    return child


def mutate_chromosome(
    chrom: Chromosome,
    rng: np.random.Generator,
    *,
    p_replace: float,
    p_insert: float,
    p_delete: float,
    alphabet: Sequence[MutatorId],
    max_length: int,
) -> Chromosome:
    """Apply replace (per-gene), then one insert, then one delete (each prob-gated)."""
    genes: list[MutatorId] = list(chrom)
    # 1. Per-gene replace.
    if alphabet:
        for i in range(len(genes)):
            if float(rng.random()) < p_replace:
                genes[i] = alphabet[int(rng.integers(0, len(alphabet)))]
    # 2. One insert (skip if already at max length).
    if alphabet and float(rng.random()) < p_insert and len(genes) < max_length:
        pos = int(rng.integers(0, len(genes) + 1))
        genes.insert(pos, alphabet[int(rng.integers(0, len(alphabet)))])
    # 3. One delete (skip if length 1).
    if float(rng.random()) < p_delete and len(genes) > 1:
        pos = int(rng.integers(0, len(genes)))
        genes.pop(pos)
    return tuple(genes)


def repair_chromosome(
    chrom: Chromosome, *, max_length: int = MAX_CHROMOSOME_LENGTH
) -> Chromosome | None:
    """Drop later genes that conflict with earlier ones; truncate; None if empty."""
    kept: list[MutatorId] = []
    for gene in chrom:
        # Проверяем совместимость с уже принятыми генами.
        compatible = True
        for prev in kept:
            try:
                prev_mut = RegistryOfMutators.by_id(prev)
            except KeyError:
                continue
            if not prev_mut.compatible_with(gene):
                compatible = False
                break
        if compatible:
            kept.append(gene)
    if not kept:
        return None
    if len(kept) > max_length:
        kept = kept[:max_length]
    return tuple(kept)


__all__ = [
    "crossover_one_point",
    "default_alphabet",
    "mutate_chromosome",
    "repair_chromosome",
    "select_top_k",
]
