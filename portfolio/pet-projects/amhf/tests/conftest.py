"""Shared pytest fixtures for AMHF tests."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from amhf.delivery.request import FuzzRequest, FuzzResponse
from amhf.utils.seeding import SeedManager


@pytest.fixture()
def repo_root() -> Path:
    """Absolute path to the repository root."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture()
def chart_output_dir(repo_root: Path) -> Path:
    """Directory for empirical-test chart artefacts (gitignored).

    Used by ``tests/integration/test_e2e_adaptive.py`` to drop convergence
    PNGs and a summary.json. The whole ``results/`` tree is gitignored, so
    these files never enter version control.
    """
    out = repo_root / "results" / "charts"
    out.mkdir(parents=True, exist_ok=True)
    return out


@pytest.fixture()
def configs_dir(repo_root: Path) -> Path:
    return repo_root / "configs"


@pytest.fixture()
def corpus_dir(repo_root: Path) -> Path:
    return repo_root / "corpus"


@pytest.fixture()
def seed_manager() -> SeedManager:
    """Deterministic SeedManager for tests."""
    return SeedManager(master_seed=20260429)


@pytest.fixture()
def rng(seed_manager: SeedManager) -> np.random.Generator:
    """Single per-test Generator named 'tests'."""
    return seed_manager.fresh("tests")


@pytest.fixture()
def sample_request() -> FuzzRequest:
    """Minimal FuzzRequest used by mutator/oracle unit tests."""
    return FuzzRequest(
        method="GET",
        url="http://localhost/vuln?id=1",
        headers={"User-Agent": "amhf/test"},
        query={"id": "1"},
        body_bytes=b"",
        attack_class="sqli",
        payload_id="sqli_taut_001",
        payload_text="' OR '1'='1",
        param_to_fuzz="id",
    )


@pytest.fixture()
def sample_response_factory():
    """Factory producing FuzzResponse with sensible defaults."""

    def _make(
        status_code: int = 200,
        body: str = "",
        elapsed_ms: float = 12.3,
        error: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> FuzzResponse:
        body_bytes = body.encode("utf-8")
        return FuzzResponse(
            status_code=status_code,
            headers=headers or {"Content-Type": "text/html; charset=utf-8"},
            body_bytes=body_bytes,
            body_text=body,
            elapsed_ms=elapsed_ms,
            error=error,
        )

    return _make
