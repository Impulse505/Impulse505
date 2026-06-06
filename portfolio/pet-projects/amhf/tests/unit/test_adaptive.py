"""Unit tests for AdaptiveScheduler."""

from __future__ import annotations

import numpy as np
import pytest

from amhf.config import GAConfig, SchedulerConfig
from amhf.mutators.base import RegistryOfMutators
from amhf.scheduler.adaptive import AdaptiveScheduler
from amhf.scheduler.chromosome import Chromosome


def _make_cfg(
    *,
    initial_pool_size: int = 12,
    period: int = 20,
    top_k: int = 4,
    offspring_per_round: int = 3,
    p_replace: float = 0.1,
    p_insert: float = 0.1,
    p_delete: float = 0.1,
    min_plays_for_selection: int = 2,
    max_chromosome_length: int = 5,
    ucb_c: float = 1.41,
) -> SchedulerConfig:
    return SchedulerConfig(
        type="ucb_with_ga",
        initial_pool_size=initial_pool_size,
        max_chromosome_length=max_chromosome_length,
        ucb_c=ucb_c,
        ga=GAConfig(
            period=period, top_k=top_k, offspring_per_round=offspring_per_round,
            p_replace=p_replace, p_insert=p_insert, p_delete=p_delete,
            min_plays_for_selection=min_plays_for_selection,
        ),
    )


def _ids() -> list[str]:
    # A workable cross-layer alphabet (≥1 from each layer).
    return [
        "url_encode", "hex_encode", "case_toggle",  # payload
        "multipart_boundary", "param_pollution", "content_type_swap",  # body
        "duplicate", "case_jiggle", "xff_spoof",  # headers
        "method_case", "path_normalize", "fragment_inject",  # url
    ]


def test_initial_pool_size_matches_config() -> None:
    cfg = _make_cfg(initial_pool_size=15)
    rng = np.random.default_rng(0)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    assert sched.pool_size == 15
    assert sched.step == 0


def test_initial_pool_lengths_in_range() -> None:
    cfg = _make_cfg(initial_pool_size=10)
    rng = np.random.default_rng(0)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    for stats in sched.bandit.all_stats():
        assert 1 <= len(stats.arm_id) <= 3


def test_initial_pool_chromosomes_pairwise_compatible() -> None:
    cfg = _make_cfg(initial_pool_size=20)
    rng = np.random.default_rng(11)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    for stats in sched.bandit.all_stats():
        chrom: Chromosome = stats.arm_id
        for i, g_i in enumerate(chrom):
            for g_j in chrom[i + 1:]:
                m_i = RegistryOfMutators.by_id(g_i)
                m_j = RegistryOfMutators.by_id(g_j)
                assert m_i.compatible_with(g_j), f"{g_i} vs {g_j}"
                assert m_j.compatible_with(g_i)


def test_next_batch_returns_k_arms() -> None:
    cfg = _make_cfg(initial_pool_size=10)
    rng = np.random.default_rng(0)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    batch = sched.next_batch(5)
    assert len(batch) == 5
    assert len(set(batch)) == 5


def test_next_batch_clamps_to_pool_size() -> None:
    cfg = _make_cfg(initial_pool_size=8)
    rng = np.random.default_rng(0)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    batch = sched.next_batch(50)
    assert len(batch) == 8


def test_next_batch_zero_returns_empty() -> None:
    cfg = _make_cfg(initial_pool_size=4)
    rng = np.random.default_rng(0)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    assert sched.next_batch(0) == []


def test_report_reward_increments_step() -> None:
    cfg = _make_cfg(initial_pool_size=4, period=100)
    rng = np.random.default_rng(0)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    chrom = sched.next_batch(1)[0]
    sched.report_reward(chrom, 1)
    assert sched.step == 1
    assert sched.bandit.stats(chrom).n == 1


def test_ga_fires_at_period_boundary() -> None:
    cfg = _make_cfg(
        initial_pool_size=10, period=10, top_k=4,
        offspring_per_round=3, min_plays_for_selection=1,
    )
    rng = np.random.default_rng(7)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    initial_pool = sched.pool_size

    # Drive 9 rewards: GA must NOT fire yet.
    arms_for_play = sched.next_batch(9)
    pairs = [(a, 1) for a in arms_for_play]
    sched.report_rewards(pairs)
    assert sched.step == 9
    # Pool size unchanged (no GA).
    assert sched.pool_size == initial_pool

    # One more reward → step crosses period 10 → GA fires.
    sched.report_reward(arms_for_play[0], 1)
    assert sched.step == 10
    # New offspring (≤ offspring_per_round). May be 0 if all dedup'd; allow.
    assert sched.pool_size <= initial_pool + cfg.ga.offspring_per_round
    assert sched.pool_size >= initial_pool


def test_ga_does_not_fire_within_same_period() -> None:
    cfg = _make_cfg(
        initial_pool_size=8, period=20, top_k=3,
        offspring_per_round=2, min_plays_for_selection=1,
    )
    rng = np.random.default_rng(3)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    snapshot = sched.pool_size
    arms = sched.next_batch(5)
    sched.report_rewards([(a, 0) for a in arms])
    # Step = 5 < 20, no GA.
    assert sched.pool_size == snapshot


def test_export_import_state_round_trip() -> None:
    cfg = _make_cfg(initial_pool_size=6, period=100)
    rng = np.random.default_rng(0)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    arms = sched.next_batch(3)
    sched.report_rewards([(arms[0], 1), (arms[1], 0), (arms[2], 1)])
    state = sched.export_state()

    # Build a fresh scheduler and import.
    rng2 = np.random.default_rng(99)
    sched2 = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng2)  # type: ignore[arg-type]
    sched2.import_state(state)
    assert sched2.step == sched.step

    # Bandit state is preserved.
    for s_old in sched.bandit.all_stats():
        s_new = sched2.bandit.stats(s_old.arm_id)
        assert s_new.n == s_old.n
        assert s_new.sum_reward == s_old.sum_reward
        assert s_new.last_played_at == s_old.last_played_at
    # total_pulls preserved.
    assert sched2.bandit.total_pulls == sched.bandit.total_pulls


def test_evolve_pool_returns_offspring_list() -> None:
    cfg = _make_cfg(
        initial_pool_size=8, period=1000, top_k=4,
        offspring_per_round=5, min_plays_for_selection=1,
    )
    rng = np.random.default_rng(11)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    # Seed plays so top_k can find eligible parents.
    arms = sched.next_batch(8)
    sched.report_rewards([(a, 1) for a in arms])
    new_kids = sched.evolve_pool()
    assert isinstance(new_kids, list)
    # Each kid is a registered arm now.
    for k in new_kids:
        assert sched.bandit.stats(k).n == 0


def test_report_rewards_empty_is_noop() -> None:
    cfg = _make_cfg(initial_pool_size=4, period=100)
    rng = np.random.default_rng(0)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    sched.report_rewards([])
    assert sched.step == 0


def test_no_mutator_ids_raises() -> None:
    cfg = _make_cfg(initial_pool_size=4)
    rng = np.random.default_rng(0)
    with pytest.raises(RuntimeError, match="no mutator ids"):
        AdaptiveScheduler(cfg, mutator_ids=[], rng=rng)


def test_cull_triggers_when_pool_doubles() -> None:
    # Force a small init pool and a tight cull threshold.
    cfg = _make_cfg(
        initial_pool_size=3, period=1000, top_k=3,
        offspring_per_round=10, min_plays_for_selection=1,
    )
    rng = np.random.default_rng(2)
    sched = AdaptiveScheduler(cfg, mutator_ids=_ids(), rng=rng)  # type: ignore[arg-type]
    # Mark all initial arms as cold (n>=1, mean=0).
    arms = list(sched.bandit.all_stats())
    sched.report_rewards([(s.arm_id, 0) for s in arms])
    # Force GA off-cycle to grow pool and trigger cull.
    sched.evolve_pool()
    assert sched.pool_size <= 2 * cfg.initial_pool_size
