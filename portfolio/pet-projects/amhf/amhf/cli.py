"""Click-based CLI: пять команд (run, list-mutators, validate, demo, version).

Этап 4: ``run`` и ``demo`` теперь работают: запускают полный цикл
оркестратора. Остальные команды без изменений.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click
from aiohttp.test_utils import TestServer
from rich.console import Console
from rich.table import Table

from amhf import __version__
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
    load_config,
)
from amhf.demo import make_mock_app
from amhf.mutators.base import RegistryOfMutators
from amhf.orchestrator import Orchestrator, RunSummary
from amhf.utils.logging import setup_logging

_console = Console()


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """AMHF — Adaptive Multi-layer HTTP Fuzzer."""


@cli.command("version")
def version_cmd() -> None:
    """Print version and exit."""
    click.echo(f"amhf {__version__}")


@cli.command("list-mutators")
def list_mutators_cmd() -> None:
    """List mutators currently registered in the global registry."""
    table = Table(title="Registered mutators")
    table.add_column("id")
    table.add_column("layer")
    ids = sorted(RegistryOfMutators.all_ids())
    if not ids:
        click.echo("No mutators registered yet (Stage 2 will populate the registry).")
        return
    for mid in ids:
        m = RegistryOfMutators.by_id(mid)
        table.add_row(m.id, m.layer.value)
    _console.print(table)


@cli.command("validate")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to a YAML config file.",
)
def validate_cmd(config_path: Path) -> None:
    """Validate a YAML config against the pydantic schema."""
    try:
        cfg = load_config(config_path)
    except Exception as exc:
        click.echo(f"INVALID: {exc}", err=True)
        sys.exit(2)
    click.echo(
        f"OK: target={cfg.target.name}, "
        f"endpoints={len(cfg.target.endpoints)}, "
        f"total_requests={cfg.run.total_requests}"
    )


@cli.command("demo")
def demo_cmd() -> None:
    """Run a 100-request demo against an embedded mock target."""
    try:
        summary = asyncio.run(_run_demo())
    except Exception as exc:
        logging.getLogger("amhf").exception("demo failed: %s", exc)
        sys.exit(1)
    _print_summary(summary)


@cli.command("run")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
)
@click.option("--seed", type=int, default=None, help="Override config seed.")
@click.option(
    "--resume",
    "resume_from",
    type=str,
    default=None,
    help="Path to a previous run directory to resume from.",
)
def run_cmd(
    config_path: Path,
    seed: int | None,
    resume_from: str | None,
) -> None:
    """Run a fuzzing experiment described by a YAML config."""
    cfg = load_config(config_path)
    if seed is not None or resume_from is not None:
        cfg = _override_run(cfg, seed=seed, resume_from=resume_from)
    setup_logging(level=cfg.logging.level)
    try:
        summary = asyncio.run(_run_with_config(cfg))
    except Exception as exc:
        logging.getLogger("amhf").exception("run failed: %s", exc)
        sys.exit(1)
    _print_summary(summary)


# --------------------------------------------------------------------------- #
# Private helpers                                                             #
# --------------------------------------------------------------------------- #


async def _run_with_config(cfg: Config) -> RunSummary:
    orch = await Orchestrator.from_config(cfg)
    try:
        summary = await orch.run_main_loop()
    finally:
        await orch.aclose()
    return summary


async def _run_demo() -> RunSummary:
    """Spin up an in-process aiohttp mock and drive 100 requests through it."""
    setup_logging(level="INFO")
    server = TestServer(make_mock_app())
    await server.start_server()
    try:
        cfg = _make_demo_config(str(server.make_url("")))
        summary = await _run_with_config(cfg)
    finally:
        await server.close()
    return summary


def _make_demo_config(base_url: str) -> Config:
    """Build a minimal Config pointing at the in-process mock target."""
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    out_dir = str(Path(tempfile.gettempdir()) / f"amhf-demo-{timestamp}")
    return Config(
        run=RunConfig(
            total_requests=100,
            concurrency=10,
            request_timeout_s=5.0,
            rate_limit_rps=200.0,
            seed=42,
            resume_from=None,
        ),
        target=TargetConfig(
            name="demo-mock",
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
            initial_pool_size=10,
            max_chromosome_length=3,
            ucb_c=1.41,
            ga=GAConfig(
                period=50,
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
            output_dir=out_dir,
            formats=["csv"],
            flush_every=20,
        ),
        logging=LoggingConfig(level="INFO", human_console=True),
    )


def _override_run(
    cfg: Config, *, seed: int | None, resume_from: str | None
) -> Config:
    """Build a new Config with run.seed / run.resume_from overridden."""
    run_dump: dict[str, Any] = cfg.run.model_dump()
    if seed is not None:
        run_dump["seed"] = seed
    if resume_from is not None:
        run_dump["resume_from"] = resume_from
    new_run = RunConfig.model_validate(run_dump)
    full_dump = cfg.model_dump()
    full_dump["run"] = new_run.model_dump()
    return Config.model_validate(full_dump)


def _print_summary(summary: RunSummary) -> None:
    table = Table(title=f"AMHF run: {summary.run_id}")
    table.add_column("metric")
    table.add_column("value", justify="right")
    table.add_row("total_attempts", str(summary.total_attempts))
    table.add_row("bypasses", str(summary.bypasses))
    table.add_row("bypass_rate", f"{summary.bypass_rate:.4f}")
    table.add_row("blocks", str(summary.blocks))
    table.add_row("server_errors", str(summary.server_errors))
    table.add_row("transport_errors", str(summary.transport_errors))
    table.add_row("pool_size_initial", str(summary.pool_size_initial))
    table.add_row("pool_size_final", str(summary.pool_size_final))
    table.add_row("elapsed_seconds", f"{summary.elapsed_seconds:.2f}")
    _console.print(table)


__all__ = ["cli"]
