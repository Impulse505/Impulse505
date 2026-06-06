"""Unit tests for UCB1Bandit."""

from __future__ import annotations

import math

import numpy as np
import pytest

from amhf.scheduler.chromosome import Chromosome
from amhf.scheduler.ucb1 import ArmStats, UCB1Bandit


def _arm(name: str) -> Chromosome:
    return (name,)  # type: ignore[return-value]


def test_empty_bandit_select_one_raises() -> None:
    b = UCB1Bandit()
    with pytest.raises(RuntimeError, match="no arms registered"):
        b.select_one()


def test_empty_bandit_select_batch_raises() -> None:
    b = UCB1Bandit()
    with pytest.raises(RuntimeError):
        b.select_batch(3)


def test_unplayed_arms_have_infinite_priority() -> None:
    b = UCB1Bandit()
    a = _arm("url_encode")
    b.add_arm(a)
    assert b.priority(a) == math.inf
    assert b.select_one() == a
    assert a in b.select_batch(5)


def test_add_arm_idempotent() -> None:
    b = UCB1Bandit()
    a = _arm("url_encode")
    b.add_arm(a)
    b.update(a, 1)
    assert b.stats(a).n == 1
    b.add_arm(a)  # second add should not reset
    assert b.stats(a).n == 1


def test_remove_arm_removes() -> None:
    b = UCB1Bandit()
    a = _arm("url_encode")
    b.add_arm(a)
    b.remove_arm(a)
    assert b.all_stats() == []
    # Remove of unknown arm — silent.
    b.remove_arm(a)


def test_update_unknown_arm_raises() -> None:
    b = UCB1Bandit()
    with pytest.raises(KeyError):
        b.update(_arm("url_encode"), 1)


def test_select_batch_no_duplicates_and_clamped() -> None:
    b = UCB1Bandit()
    arms = [_arm(f"a{i}") for i in range(4)]
    for a in arms:
        b.add_arm(a)
    batch = b.select_batch(10)
    assert len(batch) == 4
    assert len(set(batch)) == 4


def test_select_batch_zero_returns_empty() -> None:
    b = UCB1Bandit()
    b.add_arm(_arm("a"))
    assert b.select_batch(0) == []


def test_total_pulls_increments() -> None:
    b = UCB1Bandit()
    a = _arm("a")
    b.add_arm(a)
    assert b.total_pulls == 0
    b.update(a, 1)
    b.update(a, 0)
    assert b.total_pulls == 2
    assert b.stats(a).last_played_at == 2


def test_priority_formula_sane() -> None:
    b = UCB1Bandit(c=math.sqrt(2.0))
    a, c = _arm("a"), _arm("c")
    b.add_arm(a)
    b.add_arm(c)
    b.update(a, 1)
    b.update(a, 0)
    b.update(c, 1)
    # mean_a = 0.5, mean_c = 1.0, N = 3
    expected_a = 0.5 + math.sqrt(2.0) * math.sqrt(2.0 * math.log(3) / 2)
    expected_c = 1.0 + math.sqrt(2.0) * math.sqrt(2.0 * math.log(3) / 1)
    assert math.isclose(b.priority(a), expected_a, rel_tol=1e-9)
    assert math.isclose(b.priority(c), expected_c, rel_tol=1e-9)


def test_deterministic_with_fixed_seed() -> None:
    rng = np.random.default_rng(42)
    b = UCB1Bandit()
    arms = [_arm(f"a{i}") for i in range(5)]
    for a in arms:
        b.add_arm(a)
    means = [0.1, 0.3, 0.5, 0.7, 0.9]
    history: list[Chromosome] = []
    for _ in range(50):
        chosen = b.select_one()
        idx = arms.index(chosen)
        reward = int(rng.random() < means[idx])
        b.update(chosen, reward)
        history.append(chosen)

    # Re-run with the same seed; must reproduce.
    rng2 = np.random.default_rng(42)
    b2 = UCB1Bandit()
    for a in arms:
        b2.add_arm(a)
    history2: list[Chromosome] = []
    for _ in range(50):
        chosen = b2.select_one()
        idx = arms.index(chosen)
        reward = int(rng2.random() < means[idx])
        b2.update(chosen, reward)
        history2.append(chosen)

    assert history == history2


def test_arm_stats_dataclass() -> None:
    s = ArmStats(arm_id=_arm("a"))
    assert s.n == 0
    assert s.sum_reward == 0.0
    assert s.last_played_at == -1
    assert s.mean == 0.0
    s.n = 4
    s.sum_reward = 2.0
    assert s.mean == 0.5


# --------------------------------------------------------------------------- #
# 10-armed Bernoulli benchmark + logarithmic regret check                     #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def bandit_run() -> dict[str, object]:
    """Run a single 1000-step bandit experiment; reused by both tests."""
    rng = np.random.default_rng(20260429)
    arms: list[Chromosome] = [_arm(f"a{i}") for i in range(10)]
    means = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]
    best_mean = max(means)
    b = UCB1Bandit()
    for a in arms:
        b.add_arm(a)
    cum_regret_at: dict[int, float] = {}
    plays_per_arm = [0] * 10
    cum_regret = 0.0
    for t in range(1, 1001):
        chosen = b.select_one()
        idx = arms.index(chosen)
        reward = int(rng.random() < means[idx])
        b.update(chosen, reward)
        plays_per_arm[idx] += 1
        cum_regret += best_mean - means[idx]
        if t in (100, 500, 1000):
            cum_regret_at[t] = cum_regret
    return {
        "plays_per_arm": plays_per_arm,
        "cum_regret_at": cum_regret_at,
    }


def test_best_arm_pulled_at_least_30_pct(bandit_run: dict[str, object]) -> None:
    plays = bandit_run["plays_per_arm"]
    assert isinstance(plays, list)
    # arms[9] has mean 0.95 — best.
    assert plays[9] >= 300, f"best arm pulled only {plays[9]} times out of 1000"


def test_logarithmic_regret(bandit_run: dict[str, object]) -> None:
    cum = bandit_run["cum_regret_at"]
    assert isinstance(cum, dict)
    ratio = cum[1000] / max(cum[100], 1.0)
    # Linear regret would give ratio ≈ 10. Sub-linear → < 7 (logarithmic
    # rough check; gaps are small so the constant is loose).
    assert ratio < 7.0, f"regret ratio {ratio} not sub-linear"
