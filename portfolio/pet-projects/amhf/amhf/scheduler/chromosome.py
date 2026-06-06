"""Chromosome — упорядоченная цепочка идентификаторов мутаторов (FROZEN).

Хромосома является «рукой» (arm) UCB1-bandit'а и единицей кроссовера в GA.
Длина 1..MAX_CHROMOSOME_LENGTH (по умолчанию 5). Тип — tuple для
hashable/immutable семантики.
"""

from __future__ import annotations

from collections.abc import Iterable

from amhf.mutators.base import MutatorId

MAX_CHROMOSOME_LENGTH: int = 5

# Хромосома — это просто кортеж идентификаторов в каноническом порядке слоёв.
Chromosome = tuple[MutatorId, ...]


def build_chromosome(genes: Iterable[str]) -> Chromosome:
    """Build a Chromosome from an iterable of mutator-id strings.

    Validates length bounds. Element-level validation (membership in
    the MutatorId Literal) is the responsibility of the registry, since
    the Literal type alias evaporates at runtime.
    """
    chrom = tuple(genes)
    if not chrom:
        raise ValueError("Chromosome must contain at least one gene")
    if len(chrom) > MAX_CHROMOSOME_LENGTH:
        raise ValueError(
            f"Chromosome length {len(chrom)} exceeds limit {MAX_CHROMOSOME_LENGTH}"
        )
    return chrom  # type: ignore[return-value]
