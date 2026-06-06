"""Deterministic seed manager — single master seed -> per-component RNGs.

Использование:
    seeds = SeedManager(master_seed=42)
    rng_mut  = seeds.spawn("mutators")
    rng_sched = seeds.spawn("scheduler")

Каждый именованный поток выводится из master_seed через
numpy.random.SeedSequence.spawn — гарантированно независимы и
воспроизводимы при том же master_seed.
"""

from __future__ import annotations

import hashlib

import numpy as np


class SeedManager:
    """Manages per-component numpy.random.Generator instances."""

    def __init__(self, master_seed: int) -> None:
        self.master_seed = int(master_seed)
        self._root = np.random.SeedSequence(self.master_seed)
        self._cache: dict[str, np.random.Generator] = {}

    def spawn(self, name: str) -> np.random.Generator:
        """Return (and cache) a Generator for the given component name."""
        if name in self._cache:
            return self._cache[name]
        # Имя компонента детерминированно отображаем в 32-битный entropy-добавок,
        # чтобы порядок вызовов не влиял на распределение зерён между компонентами.
        digest = hashlib.blake2b(name.encode("utf-8"), digest_size=4).digest()
        offset = int.from_bytes(digest, "big") & 0x7FFFFFFF
        seq = np.random.SeedSequence([self.master_seed, offset])
        rng = np.random.default_rng(seq)
        self._cache[name] = rng
        return rng

    def fresh(self, name: str) -> np.random.Generator:
        """Return a NEW Generator for ``name``, discarding any cached one."""
        self._cache.pop(name, None)
        return self.spawn(name)


__all__ = ["SeedManager"]
