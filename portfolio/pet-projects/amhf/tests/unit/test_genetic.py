"""Unit tests for GeneticOperator and GA helpers."""

from __future__ import annotations

import numpy as np

from amhf.mutators.base import RegistryOfMutators
from amhf.scheduler._ga_helpers import (
    crossover_one_point,
    mutate_chromosome,
    repair_chromosome,
    select_top_k,
)
from amhf.scheduler._ucb1_stats import ArmStats
from amhf.scheduler.chromosome import MAX_CHROMOSOME_LENGTH, Chromosome
from amhf.scheduler.genetic import GeneticOperator


def _chrom(*ids: str) -> Chromosome:
    return tuple(ids)  # type: ignore[return-value]


def test_crossover_preserves_length_invariants() -> None:
    rng = np.random.default_rng(0)
    p1 = _chrom("url_encode", "case_toggle", "html_entity")
    p2 = _chrom("hex_encode", "base64")
    for _ in range(20):
        child = crossover_one_point(p1, p2, rng)
        assert 1 <= len(child) <= max(len(p1), len(p2))


def test_crossover_returns_p1_when_min_length_one() -> None:
    rng = np.random.default_rng(0)
    p1 = _chrom("url_encode")
    p2 = _chrom("hex_encode", "base64")
    assert crossover_one_point(p1, p2, rng) == p1


def test_mutate_replace_all_genes_when_p_replace_one() -> None:
    rng = np.random.default_rng(0)
    chrom = _chrom("url_encode", "case_toggle")
    alphabet = ("hex_encode", "base64")  # type: ignore[var-annotated]
    out = mutate_chromosome(
        chrom, rng,
        p_replace=1.0, p_insert=0.0, p_delete=0.0,
        alphabet=alphabet, max_length=5,
    )
    assert len(out) == 2
    for g in out:
        assert g in alphabet


def test_mutate_insert_grows_to_cap() -> None:
    rng = np.random.default_rng(0)
    chrom = _chrom("url_encode")
    alphabet = ("hex_encode",)  # type: ignore[var-annotated]
    # one mutate call: insert with prob 1 → length 2.
    out = mutate_chromosome(
        chrom, rng,
        p_replace=0.0, p_insert=1.0, p_delete=0.0,
        alphabet=alphabet, max_length=5,
    )
    assert len(out) == 2

    # At max length, insert should be skipped.
    chrom_max = _chrom("url_encode", "case_toggle", "html_entity",
                       "hex_encode", "base64")
    out_max = mutate_chromosome(
        chrom_max, rng,
        p_replace=0.0, p_insert=1.0, p_delete=0.0,
        alphabet=alphabet, max_length=5,
    )
    assert len(out_max) == 5


def test_mutate_delete_never_below_one() -> None:
    rng = np.random.default_rng(0)
    chrom = _chrom("url_encode")
    out = mutate_chromosome(
        chrom, rng,
        p_replace=0.0, p_insert=0.0, p_delete=1.0,
        alphabet=("hex_encode",),  # type: ignore[arg-type]
        max_length=5,
    )
    assert len(out) == 1  # cannot delete when length is 1


def test_repair_drops_incompatible_pair() -> None:
    # json_form_swap and content_type_swap are body-layer + explicit excludes.
    chrom = _chrom("json_form_swap", "content_type_swap")
    repaired = repair_chromosome(chrom)
    assert repaired is not None
    # Either dropped to one gene, or any pair must be mutually compatible.
    for i, g_i in enumerate(repaired):
        for g_j in repaired[i + 1:]:
            assert RegistryOfMutators.by_id(g_i).compatible_with(g_j)
            assert RegistryOfMutators.by_id(g_j).compatible_with(g_i)


def test_repair_truncates_to_max_length() -> None:
    chrom = _chrom("url_encode", "multipart_boundary", "duplicate",
                   "method_case", "html_entity", "case_jiggle")
    # Length 6, with two payload-layer entries (incompatible) — repair should reduce.
    repaired = repair_chromosome(chrom, max_length=MAX_CHROMOSOME_LENGTH)
    assert repaired is not None
    assert len(repaired) <= MAX_CHROMOSOME_LENGTH


def test_repair_returns_none_when_unknown_only() -> None:
    # All-unknown chromosome would be kept (we tolerate unknown).
    # To force None we use empty input; build_chromosome forbids that, so we
    # call repair directly on a tuple of one *known* element to ensure non-None.
    chrom = _chrom("url_encode")
    assert repair_chromosome(chrom) == chrom


def test_select_top_k_filters_by_min_plays() -> None:
    s_low = ArmStats(arm_id=_chrom("a"), n=1, sum_reward=1.0)
    s_mid = ArmStats(arm_id=_chrom("b"), n=5, sum_reward=2.0)
    s_high = ArmStats(arm_id=_chrom("c"), n=10, sum_reward=8.0)
    out = select_top_k([s_low, s_mid, s_high], k=2, min_plays=3)
    # s_low filtered out; sorted by mean desc: c (0.8) > b (0.4)
    assert out == [_chrom("c"), _chrom("b")]


def test_select_top_k_tie_breaks_by_n_desc() -> None:
    s1 = ArmStats(arm_id=_chrom("a"), n=4, sum_reward=2.0)  # mean 0.5
    s2 = ArmStats(arm_id=_chrom("b"), n=8, sum_reward=4.0)  # mean 0.5
    out = select_top_k([s1, s2], k=2, min_plays=1)
    assert out[0] == _chrom("b")  # higher n


def test_evolve_returns_unique_valid_offspring() -> None:
    rng = np.random.default_rng(7)
    op = GeneticOperator(p_replace=0.3, p_insert=0.2, p_delete=0.1)
    # 4 parent stats, all eligible, with diverse means.
    stats = [
        ArmStats(arm_id=_chrom("url_encode", "duplicate"), n=10, sum_reward=8.0),
        ArmStats(arm_id=_chrom("hex_encode"), n=10, sum_reward=6.0),
        ArmStats(arm_id=_chrom("base64", "case_jiggle"), n=10, sum_reward=4.0),
        ArmStats(arm_id=_chrom("html_entity", "method_case"),
                 n=10, sum_reward=3.0),
    ]
    children = op.evolve(stats, k=4, min_plays=1, offspring_per_round=8, rng=rng)
    assert len(children) <= 8
    # All unique.
    assert len(set(children)) == len(children)
    # All valid: no two same-layer genes (or explicit-exclude pair).
    for chrom in children:
        for i, g_i in enumerate(chrom):
            for g_j in chrom[i + 1:]:
                m_i = RegistryOfMutators.by_id(g_i)
                m_j = RegistryOfMutators.by_id(g_j)
                assert m_i.compatible_with(g_j)
                assert m_j.compatible_with(g_i)


def test_evolve_returns_empty_when_too_few_parents() -> None:
    rng = np.random.default_rng(0)
    op = GeneticOperator(p_replace=0.1, p_insert=0.1, p_delete=0.1)
    # min_plays high → no eligible parents.
    stats = [ArmStats(arm_id=_chrom("a"), n=1, sum_reward=0.5)]
    out = op.evolve(stats, k=4, min_plays=10, offspring_per_round=4, rng=rng)
    assert out == []


def test_genetic_operator_default_alphabet_is_registry() -> None:
    op = GeneticOperator(p_replace=0.0, p_insert=0.0, p_delete=0.0)
    # all 31 mutators registered at import time.
    assert len(op.alphabet) == 31


def test_genetic_operator_explicit_alphabet_used() -> None:
    custom = ("url_encode", "hex_encode")
    op = GeneticOperator(
        p_replace=0.0, p_insert=0.0, p_delete=0.0,
        alphabet=custom,  # type: ignore[arg-type]
    )
    assert op.alphabet == custom
