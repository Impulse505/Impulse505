"""Unit tests for amhf.cli — run / demo / validate behavior at CLI level."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from amhf.cli import cli


def test_demo_exits_zero() -> None:
    """``amhf demo`` runs an in-process loop end-to-end and exits 0."""
    runner = CliRunner()
    result = runner.invoke(cli, ["demo"], catch_exceptions=False)
    assert result.exit_code == 0, result.output


def test_run_with_synthetic_config(tmp_path: Path) -> None:
    """``amhf run -c <path>`` against a synthetic config drives the loop end-to-end."""
    # We generate a minimal config that points at a HTTP target that doesn't
    # actually need to be live — request failures will be classified as
    # transport_error but the orchestrator must still complete with exit 0.
    out_dir = tmp_path / "results"
    cfg_data = {
        "run": {
            "total_requests": 5,
            "concurrency": 2,
            "request_timeout_s": 0.5,
            "rate_limit_rps": 100.0,
            "seed": 7,
            "resume_from": None,
        },
        "target": {
            "name": "synthetic",
            "base_url": "http://127.0.0.1:1",  # no listener -> transport errors
            "endpoints": [
                {
                    "path": "/sqli",
                    "method": "GET",
                    "params": {"id": "1"},
                    "attack_class": "sqli",
                    "param_to_fuzz": "id",
                },
            ],
        },
        "corpus": {
            "paths": ["corpus/sqli.yaml"],
            "filter_class": "sqli",
        },
        "scheduler": {
            "type": "ucb_with_ga",
            "initial_pool_size": 4,
            "max_chromosome_length": 2,
            "ucb_c": 1.41,
            "ga": {
                "period": 10,
                "top_k": 2,
                "offspring_per_round": 2,
                "p_replace": 0.1,
                "p_insert": 0.0,
                "p_delete": 0.0,
                "min_plays_for_selection": 1,
            },
        },
        "mutators": {
            "payload": ["url_encode", "case_toggle"],
        },
        "oracle": {
            "waf": {
                "blocked_codes": [403],
                "blocked_body_signatures": ["ModSecurity"],
            },
        },
        "storage": {
            "output_dir": str(out_dir),
            "formats": ["csv"],
            "flush_every": 5,
        },
        "logging": {"level": "WARNING", "human_console": False},
    }
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["run", "-c", str(cfg_path)], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert (out_dir / "attempts.csv").exists()
    assert (out_dir / "summary.json").exists()


def test_run_seed_override(tmp_path: Path) -> None:
    """``--seed N`` overrides config seed — exits 0 just the same."""
    out_dir = tmp_path / "results"
    cfg_data = {
        "run": {
            "total_requests": 3, "concurrency": 1, "request_timeout_s": 0.5,
            "rate_limit_rps": 100.0, "seed": 1, "resume_from": None,
        },
        "target": {
            "name": "x", "base_url": "http://127.0.0.1:1",
            "endpoints": [{
                "path": "/sqli", "method": "GET", "params": {},
                "attack_class": "sqli", "param_to_fuzz": "id",
            }],
        },
        "corpus": {"paths": ["corpus/sqli.yaml"], "filter_class": "sqli"},
        "scheduler": {
            "type": "ucb_with_ga", "initial_pool_size": 3,
            "max_chromosome_length": 2, "ucb_c": 1.41,
            "ga": {
                "period": 10, "top_k": 2, "offspring_per_round": 2,
                "p_replace": 0.1, "p_insert": 0.0, "p_delete": 0.0,
                "min_plays_for_selection": 1,
            },
        },
        "mutators": {"payload": ["url_encode"]},
        "oracle": {"waf": {"blocked_codes": [403], "blocked_body_signatures": []}},
        "storage": {
            "output_dir": str(out_dir), "formats": ["csv"], "flush_every": 1,
        },
        "logging": {"level": "WARNING", "human_console": False},
    }
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["run", "-c", str(cfg_path), "--seed", "999"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output


def test_validate_invalid_config_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not_a_dict\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["validate", "-c", str(bad)])
    assert result.exit_code == 2
    assert "INVALID" in result.output


@pytest.mark.parametrize("cmd", [["version"], ["list-mutators"]])
def test_smoke_subcommands(cmd: list[str]) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, cmd)
    assert result.exit_code == 0
