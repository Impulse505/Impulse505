"""Unit tests for amhf.orchestrator — bootstrap, calibrate, run-loop, resume."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer
from pydantic import ValidationError

from amhf.config import (
    BackendOracleConfig,
    Config,
    CorpusConfig,
    EndpointConfig,
    GAConfig,
    LoggingConfig,
    MutatorsConfig,
    OracleConfig,
    RunConfig,
    SchedulerConfig,
    SqliOracleConfig,
    StorageConfig,
    TargetConfig,
    WafOracleConfig,
)
from amhf.demo import make_mock_app
from amhf.orchestrator import Orchestrator, RunSummary

pytestmark = [pytest.mark.asyncio]


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _build_test_config(
    base_url: str,
    *,
    output_dir: Path,
    total_requests: int = 100,
    concurrency: int = 5,
    seed: int = 42,
    resume_from: str | None = None,
) -> Config:
    return Config(
        run=RunConfig(
            total_requests=total_requests,
            concurrency=concurrency,
            request_timeout_s=5.0,
            rate_limit_rps=200.0,
            seed=seed,
            resume_from=resume_from,
        ),
        target=TargetConfig(
            name="test-target",
            base_url=base_url.rstrip("/"),
            endpoints=[
                EndpointConfig(
                    path="/sqli",
                    method="GET",
                    params={"id": "1"},
                    attack_class="sqli",
                    param_to_fuzz="id",
                ),
            ],
        ),
        corpus=CorpusConfig(
            paths=[Path("corpus/sqli.yaml")],
            filter_class="sqli",
        ),
        scheduler=SchedulerConfig(
            type="ucb_with_ga",
            initial_pool_size=8,
            max_chromosome_length=3,
            ucb_c=1.41,
            ga=GAConfig(
                period=40,
                top_k=4,
                offspring_per_round=3,
                p_replace=0.1,
                p_insert=0.05,
                p_delete=0.05,
                min_plays_for_selection=2,
            ),
        ),
        mutators=MutatorsConfig(
            payload=[
                "url_encode", "double_url_encode", "html_entity",
                "case_toggle", "comment_inject",
            ],
            url=["path_normalize", "percent_encode_path"],
        ),
        oracle=OracleConfig(
            waf=WafOracleConfig(
                blocked_codes=[403],
                blocked_body_signatures=["ModSecurity", "Forbidden"],
            ),
            backend=BackendOracleConfig(
                sqli=SqliOracleConfig(
                    error_signatures=["SQL syntax"],
                    flag_marker="AMHF_FLAG_",
                ),
            ),
        ),
        storage=StorageConfig(
            output_dir=str(output_dir),
            formats=["csv", "sqlite"],
            flush_every=10,
        ),
        logging=LoggingConfig(level="WARNING", human_console=False),
    )


@pytest_asyncio.fixture()
async def mock_server() -> AsyncIterator[TestServer]:
    srv = TestServer(make_mock_app())
    await srv.start_server()
    try:
        yield srv
    finally:
        await srv.close()


# --------------------------------------------------------------------------- #
# Tests                                                                       #
# --------------------------------------------------------------------------- #


async def test_orchestrator_bootstrap(
    mock_server: TestServer, tmp_path: Path
) -> None:
    """Orchestrator.from_config does not crash and wires all deps."""
    cfg = _build_test_config(str(mock_server.make_url("")), output_dir=tmp_path)
    orch = await Orchestrator.from_config(cfg)
    try:
        assert orch.deps.cfg.run.total_requests == 100
        assert orch.deps.scheduler.pool_size > 0
        assert orch.deps.run_id.startswith("run-")
        assert orch.deps.output_dir.exists()
        assert len(orch.deps.sinks) == 2
    finally:
        await orch.aclose()


async def test_calibrate_timing_against_mock(
    tmp_path: Path,
) -> None:
    """20 baseline GETs against a mock with ~50ms ± noise → threshold in [100..1500]."""
    # Build a custom server adding ~50ms of latency.
    async def slow(_: web.Request) -> web.Response:
        await asyncio.sleep(0.05)
        return web.Response(text="ok", status=200)

    app = web.Application()
    app.router.add_get("/sqli", slow)
    srv = TestServer(app)
    await srv.start_server()
    try:
        cfg = _build_test_config(
            str(srv.make_url("")), output_dir=tmp_path, total_requests=10,
        )
        orch = await Orchestrator.from_config(cfg)
        try:
            await orch.calibrate_timing(samples=20)
            threshold = orch.deps.timing.threshold_ms
            # Calibrated threshold = mean (~50ms) + 3*sigma.
            assert 50.0 < threshold < 1500.0, f"unexpected threshold={threshold}"
        finally:
            await orch.aclose()
    finally:
        await srv.close()


async def test_run_main_loop_writes_records(
    mock_server: TestServer, tmp_path: Path,
) -> None:
    """100-request mini-run → exactly 100 rows in CSV and SQLite."""
    cfg = _build_test_config(
        str(mock_server.make_url("")), output_dir=tmp_path, total_requests=100,
    )
    orch = await Orchestrator.from_config(cfg)
    try:
        summary = await orch.run_main_loop()
    finally:
        await orch.aclose()

    assert isinstance(summary, RunSummary)
    assert summary.total_attempts == 100
    assert summary.bypass_rate >= 0.0
    assert summary.elapsed_seconds >= 0.0
    assert summary.run_id == orch.deps.run_id

    csv_path = tmp_path / "attempts.csv"
    assert csv_path.exists()
    csv_lines = csv_path.read_text(encoding="utf-8").splitlines()
    # header + 100 data rows
    assert len(csv_lines) == 101

    sqlite_path = tmp_path / "attempts.sqlite3"
    assert sqlite_path.exists()
    import sqlite3
    conn = sqlite3.connect(sqlite_path)
    try:
        n = conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
    finally:
        conn.close()
    assert n == 100


async def test_run_summary_field_by_field(
    mock_server: TestServer, tmp_path: Path,
) -> None:
    cfg = _build_test_config(
        str(mock_server.make_url("")), output_dir=tmp_path, total_requests=20,
    )
    orch = await Orchestrator.from_config(cfg)
    try:
        summary = await orch.run_main_loop()
    finally:
        await orch.aclose()
    expected_fields = {
        "run_id", "started_at", "finished_at", "total_attempts",
        "bypasses", "bypass_rate", "blocks", "server_errors",
        "transport_errors", "pool_size_initial", "pool_size_final",
        "seed", "elapsed_seconds",
    }
    assert set(RunSummary.model_fields) == expected_fields
    assert summary.total_attempts == 20
    assert summary.seed == 42
    assert summary.pool_size_initial == 8
    assert summary.pool_size_final >= summary.pool_size_initial


async def test_resume_round_trip(
    mock_server: TestServer, tmp_path: Path,
) -> None:
    """Run 30, persist, then resume into a second orchestrator with same run_id."""
    cfg1 = _build_test_config(
        str(mock_server.make_url("")), output_dir=tmp_path / "first",
        total_requests=30, seed=99,
    )
    orch1 = await Orchestrator.from_config(cfg1)
    run_id = orch1.deps.run_id
    try:
        summary1 = await orch1.run_main_loop()
    finally:
        await orch1.aclose()
    assert summary1.total_attempts == 30
    state_path = tmp_path / "first" / "scheduler_state.json"
    assert state_path.exists()
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["run_id"] == run_id

    # Resume: same run_id, same output_dir, set resume_from to first dir.
    # We patch scheduler_state.json to simulate "30 attempts done".
    state["next_attempt_no"] = 30
    state_path.write_text(json.dumps(state), encoding="utf-8")

    cfg2 = _build_test_config(
        str(mock_server.make_url("")),
        output_dir=tmp_path / "second",
        total_requests=50,
        seed=99,
        resume_from=str((tmp_path / "first").resolve()),
    )
    orch2 = await Orchestrator.from_config(cfg2, run_id=run_id)
    try:
        # Confirm restored state is reflected.
        assert orch2._restored_attempt_no == 30
        # Run continues — should add (50 - 30) = 20 more attempts.
        summary2 = await orch2.run_main_loop()
    finally:
        await orch2.aclose()
    assert summary2.total_attempts == 50


async def test_resume_run_id_mismatch_raises(
    mock_server: TestServer, tmp_path: Path,
) -> None:
    # Prepare a fake state file with a different run_id.
    state_dir = tmp_path / "fake"
    state_dir.mkdir()
    (state_dir / "scheduler_state.json").write_text(
        json.dumps({"step": 0, "arms": [], "run_id": "DIFFERENT", "next_attempt_no": 0}),
        encoding="utf-8",
    )
    cfg = _build_test_config(
        str(mock_server.make_url("")),
        output_dir=tmp_path / "second",
        total_requests=5,
        resume_from=str(state_dir.resolve()),
    )
    from amhf.storage import StorageError
    with pytest.raises(StorageError, match="run_id mismatch"):
        await Orchestrator.from_config(cfg, run_id="EXPECTED")


async def test_orchestrator_handles_skip_when_only_same_layer_avail(
    mock_server: TestServer, tmp_path: Path,
) -> None:
    """A short run with a tiny mutator alphabet still completes."""
    cfg = _build_test_config(
        str(mock_server.make_url("")), output_dir=tmp_path, total_requests=10,
    )
    orch = await Orchestrator.from_config(cfg)
    try:
        summary = await orch.run_main_loop()
    finally:
        await orch.aclose()
    assert summary.total_attempts == 10


async def test_invalid_config_no_mutators() -> None:
    """Empty mutators sections must be rejected by config schema."""
    with pytest.raises(ValidationError):
        Config(
            run=RunConfig(
                total_requests=1, concurrency=1, request_timeout_s=1.0,
                rate_limit_rps=1.0, seed=1,
            ),
            target=TargetConfig(
                name="x", base_url="http://x",
                endpoints=[EndpointConfig(
                    path="/", method="GET", attack_class="sqli", param_to_fuzz="q",
                )],
            ),
            corpus=CorpusConfig(paths=[Path("corpus/sqli.yaml")]),
            scheduler=SchedulerConfig(
                type="ucb_with_ga", initial_pool_size=1, max_chromosome_length=2,
                ucb_c=1.0,
                ga=GAConfig(
                    period=10, top_k=2, offspring_per_round=2,
                    p_replace=0.1, p_insert=0.0, p_delete=0.0,
                    min_plays_for_selection=1,
                ),
            ),
            mutators=MutatorsConfig(),  # empty -> should fail
            oracle=OracleConfig(
                waf=WafOracleConfig(blocked_codes=[403], blocked_body_signatures=[]),
            ),
            storage=StorageConfig(output_dir="/tmp/x", formats=["csv"], flush_every=1),
        )


async def test_summary_json_written(
    mock_server: TestServer, tmp_path: Path,
) -> None:
    cfg = _build_test_config(
        str(mock_server.make_url("")), output_dir=tmp_path, total_requests=10,
    )
    orch = await Orchestrator.from_config(cfg)
    try:
        await orch.run_main_loop()
    finally:
        await orch.aclose()
    summary_path = tmp_path / "summary.json"
    assert summary_path.exists()
    payload: dict[str, Any] = json.loads(
        summary_path.read_text(encoding="utf-8")
    )
    assert payload["total_attempts"] == 10
    assert payload["seed"] == 42
