"""Stage 6 experiment runner.

Runs all generated scenario configs from ``configs/scenarios/`` (and the
FPR sub-directory) sequentially via ``amhf run``. Captures per-scenario
exit code, wall-clock, and the summary.json that the orchestrator emits.

Usage::

    python scripts/run_experiments.py [--filter <substring>] [--dry-run]
                                       [--seed N] [--total N]

``--seed`` overrides ``run.seed`` for every scenario (multi-seed mode);
``--total`` overrides ``run.total_requests`` (and proportionally scales
the FPR mini-runs). Both are no-ops if absent.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Any

from amhf.config import Config, RunConfig, load_config
from amhf.orchestrator import Orchestrator

SCENARIOS_DIR = Path("configs") / "scenarios"
FPR_DIR = SCENARIOS_DIR / "fpr"
FPR_SCALE = 0.1  # FPR mini-run uses 10% of main --total


def _collect_configs(filter_substring: str | None) -> list[Path]:
    paths: list[Path] = []
    for p in sorted(SCENARIOS_DIR.glob("*.yaml")):
        if filter_substring and filter_substring not in p.name:
            continue
        paths.append(p)
    for p in sorted(FPR_DIR.glob("*.yaml")):
        if filter_substring and filter_substring not in p.name:
            continue
        paths.append(p)
    return paths


def _override_run(
    cfg: Config, *, seed: int | None, total: int | None, is_fpr: bool
) -> Config:
    """Return a Config with run.seed / run.total_requests overridden in-place.

    For FPR configs, ``--total`` is scaled by ``FPR_SCALE`` to keep the
    benign-traffic mini-run small but still proportional to the main run.
    """
    if seed is None and total is None:
        return cfg
    run_dump: dict[str, Any] = cfg.run.model_dump()
    if seed is not None:
        run_dump["seed"] = seed
    if total is not None:
        run_dump["total_requests"] = max(20, int(total * FPR_SCALE)) if is_fpr else total
    new_run = RunConfig.model_validate(run_dump)
    full_dump: dict[str, Any] = cfg.model_dump()
    full_dump["run"] = new_run.model_dump()
    return Config.model_validate(full_dump)


async def _run_one(
    config_path: Path, *, seed: int | None, total: int | None
) -> tuple[bool, float, dict[str, Any]]:
    cfg = load_config(config_path)
    is_fpr = config_path.parent.name == "fpr"
    cfg = _override_run(cfg, seed=seed, total=total, is_fpr=is_fpr)
    started = time.monotonic()
    orch = await Orchestrator.from_config(cfg)
    try:
        summary = await orch.run_main_loop()
    finally:
        await orch.aclose()
    elapsed = time.monotonic() - started
    return True, elapsed, summary.model_dump(mode="json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--filter", default=None,
                        help="run only configs whose filename contains this substring")
    parser.add_argument("--dry-run", action="store_true",
                        help="list configs without running")
    parser.add_argument("--seed", type=int, default=None,
                        help="override run.seed for every scenario in this batch")
    parser.add_argument("--total", type=int, default=None,
                        help="override run.total_requests (FPR scales by 10%%)")
    args = parser.parse_args()

    configs = _collect_configs(args.filter)
    print(f"selected {len(configs)} configs"
          f"{f' (seed={args.seed})' if args.seed is not None else ''}"
          f"{f' (total={args.total})' if args.total is not None else ''}")
    for p in configs:
        print(f"  {p}")
    if args.dry_run:
        return 0

    results: list[dict[str, Any]] = []
    overall_started = time.monotonic()
    for cfg_path in configs:
        print(f"\n=== running {cfg_path.name} ===")
        try:
            ok, elapsed, summary = asyncio.run(
                _run_one(cfg_path, seed=args.seed, total=args.total)
            )
        except Exception as exc:  # we deliberately keep batch running
            print(f"  ERROR {cfg_path.name}: {exc!r}")
            results.append({
                "config": str(cfg_path),
                "ok": False,
                "elapsed_s": 0.0,
                "error": repr(exc),
            })
            continue
        bypass_rate = summary.get("bypass_rate", 0.0)
        bypasses = summary.get("bypasses", 0)
        blocks = summary.get("blocks", 0)
        total = summary.get("total_attempts", 0)
        print(
            f"  OK in {elapsed:5.1f}s — bypass_rate={bypass_rate:.4f} "
            f"({bypasses}/{total}, blocks={blocks})"
        )
        results.append({
            "config": str(cfg_path),
            "ok": ok,
            "elapsed_s": round(elapsed, 2),
            "summary": summary,
        })

    total_elapsed = time.monotonic() - overall_started
    out_dir = Path("results")
    out_dir.mkdir(exist_ok=True)
    suffix = f"-seed{args.seed}" if args.seed is not None else ""
    summary_path = out_dir / f"experiments_index{suffix}.json"
    with summary_path.open("w", encoding="utf-8") as fh:
        json.dump({"runs": results, "total_elapsed_s": round(total_elapsed, 2),
                   "seed": args.seed, "total_override": args.total},
                  fh, ensure_ascii=False, indent=2, default=str)
    print(f"\n=== done in {total_elapsed:.1f}s — index: {summary_path} ===")
    # Fail-loud если хоть один run упал.
    failed = [r for r in results if not r.get("ok")]
    if failed:
        print(f"FAILED: {len(failed)} runs")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
