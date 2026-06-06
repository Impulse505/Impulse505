"""Stage 6 results aggregator — graphs and summary CSV.

Reads every ``results/run-*/`` produced by Stage-6 experiments, joins
the SQLite/JSONL records into a single pandas DataFrame, and emits:

  results/charts/bypass_rate_by_scenario.png        — bar chart with 95% CI error bars
  results/charts/convergence_<waf>.png              — rolling bypass-rate over time
  results/charts/time_to_first_bypass.png           — boxplot
  results/charts/fpr_legitimate_traffic.png         — FPR per WAF with 95% CI
  results/charts/bypass_rate_distribution.png       — per-seed boxplot
  results/summary_table.csv                         — single-seed flat table
  results/summary_multi_seed.csv                    — multi-seed CI table

Multi-seed mode is automatic: when the loaded data contains
more than one distinct seed, the aggregator computes per-(scenario, waf)
mean/std across seeds AND the pooled Wilson 95% confidence interval.

Run from the repo root after ``python scripts/run_experiments.py``::

    python scripts/collect_results.py
"""

from __future__ import annotations

import json
import math
import sqlite3
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

RESULTS_DIR = Path("results")
CHARTS_DIR = RESULTS_DIR / "charts"


def _parse_run_dir(run_dir: Path) -> dict[str, str] | None:
    """Extract scenario/waf/backend from the folder name.

    Folder format depends on the orchestrator's output_dir template:
      Main:  ``run-<YYYYMMDD>-<HHMMSS>-<scenario>-<waf>-<backend>``
      FPR:   ``run-<YYYYMMDD>-<HHMMSS>-fpr-<waf>``
    Tokens: ['run', YYYYMMDD, HHMMSS, scenario, waf?, backend?]
    """
    parts = run_dir.name.split("-")
    if len(parts) < 4 or parts[0] != "run":
        return None
    if len(parts) == 5 and parts[3] == "fpr":
        # run-YYYYMMDD-HHMMSS-fpr-<waf>
        return {"scenario": "fpr", "waf": parts[4], "backend": "flag"}
    if len(parts) == 6:
        # run-YYYYMMDD-HHMMSS-<scenario>-<waf>-<backend>
        return {"scenario": parts[3], "waf": parts[4], "backend": parts[5]}
    return None


def _load_attempts(run_dir: Path) -> pd.DataFrame:
    """Read the attempts.sqlite3 (preferred) or attempts.jsonl from a run dir."""
    sqlite_path = run_dir / "attempts.sqlite3"
    if sqlite_path.exists():
        with sqlite3.connect(sqlite_path) as conn:
            df = pd.read_sql_query("SELECT * FROM attempts", conn)
        return df
    jsonl_path = run_dir / "attempts.jsonl"
    if jsonl_path.exists():
        rows = [json.loads(line) for line in jsonl_path.read_text(
            encoding="utf-8").splitlines() if line.strip()]
        return pd.DataFrame(rows)
    return pd.DataFrame()


def _gather_runs() -> pd.DataFrame:
    """Collect every Stage-6 run into a single labelled DataFrame."""
    frames: list[pd.DataFrame] = []
    for run_dir in sorted(RESULTS_DIR.glob("run-*")):
        meta = _parse_run_dir(run_dir)
        if meta is None:
            print(f"  skip {run_dir.name} (unparseable)")
            continue
        df = _load_attempts(run_dir)
        if df.empty:
            print(f"  skip {run_dir.name} (no attempts)")
            continue
        for k, v in meta.items():
            df[k] = v
        df["run_dir"] = run_dir.name
        frames.append(df)
        print(f"  loaded {run_dir.name}: {len(df)} attempts")
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def _ensure_bool(series: pd.Series) -> pd.Series:
    """Cast SQLite-backed 0/1 columns to bool reliably."""
    return series.astype(bool) if series.dtype != bool else series


def _bypass_rate(df: pd.DataFrame) -> float:
    if df.empty:
        return 0.0
    return float(_ensure_bool(df["bypass"]).sum() / len(df))


def _block_rate(df: pd.DataFrame) -> float:
    if df.empty:
        return 0.0
    return float(_ensure_bool(df["waf_blocked"]).sum() / len(df))


# --------------------------------------------------------------------------- #
# Multi-seed helpers — Wilson CI and per-(scenario, waf) summary.              #
# --------------------------------------------------------------------------- #


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% confidence interval for a binomial proportion.

    Reference: Wilson, E. B. (1927). "Probable inference, the law of
    succession, and statistical inference". JASA 22 (158): 209-212.
    Returns ``(lo, hi)`` clamped to ``[0.0, 1.0]``. If ``n == 0`` returns
    ``(0.0, 1.0)`` (totally uninformative interval).
    """
    if n <= 0:
        return (0.0, 1.0)
    p_hat = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    half = (z * math.sqrt(p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def per_seed_rates(
    df: pd.DataFrame, *, group_cols: tuple[str, ...] = ("scenario", "waf"),
    success_col: str = "bypass",
) -> pd.DataFrame:
    """Per-(group, seed) success rate. Returns DataFrame with one row per
    (group..., seed) combination, including ``rate`` and ``n``."""
    if df.empty:
        return pd.DataFrame()
    rows: list[dict[str, Any]] = []
    keys = [*list(group_cols), "seed"]
    for key, chunk in df.groupby(keys):
        bools = _ensure_bool(chunk[success_col])
        n = len(chunk)
        successes = int(bools.sum())
        row: dict[str, Any] = dict(zip(keys, key, strict=True))
        row.update({
            "n": n,
            "successes": successes,
            "rate": float(successes / n) if n else 0.0,
        })
        rows.append(row)
    return pd.DataFrame(rows)


def pooled_summary(
    df: pd.DataFrame, *, group_cols: tuple[str, ...] = ("scenario", "waf"),
    success_col: str = "bypass",
) -> pd.DataFrame:
    """For each group: pool all attempts across seeds, compute Wilson CI95
    on the pooled rate, and per-seed mean/std for inter-seed variability.

    Output columns: <group_cols...>, n_seeds, n_attempts_total, successes_total,
    rate_pooled, ci95_lo, ci95_hi, rate_mean_per_seed, rate_std_per_seed.
    """
    if df.empty:
        return pd.DataFrame()
    per_seed = per_seed_rates(df, group_cols=group_cols, success_col=success_col)
    rows: list[dict[str, Any]] = []
    for key, chunk in df.groupby(list(group_cols)):
        bools = _ensure_bool(chunk[success_col])
        n_total = len(chunk)
        succ_total = int(bools.sum())
        rate_pooled = float(succ_total / n_total) if n_total else 0.0
        ci_lo, ci_hi = wilson_ci(succ_total, n_total)
        seed_view = per_seed
        for col, val in zip(group_cols, key, strict=True):
            seed_view = seed_view[seed_view[col] == val]
        rates = seed_view["rate"].astype(float).to_numpy()
        n_seeds = len(rates)
        row: dict[str, Any] = dict(zip(group_cols, key, strict=True))
        row.update({
            "n_seeds": n_seeds,
            "n_attempts_total": n_total,
            "successes_total": succ_total,
            "rate_pooled": rate_pooled,
            "ci95_lo": ci_lo,
            "ci95_hi": ci_hi,
            "rate_mean_per_seed": float(rates.mean()) if n_seeds else 0.0,
            "rate_std_per_seed": float(rates.std(ddof=1)) if n_seeds > 1 else 0.0,
        })
        rows.append(row)
    return pd.DataFrame(rows)


def write_single_vs_multi_seed_comparison(
    df: pd.DataFrame, *, baseline_seed: int = 42,
) -> Path:
    """Build the comparison CSV.

    For each (scenario, waf): single-seed (seed=42) bypass_rate vs the
    pooled multi-seed bypass_rate with Wilson 95% CI, plus a
    'qualitative_change' flag that fires when the seed=42 cell was 0.0%
    and the pooled cell is > 0.0%, or vice versa.
    """
    out = RESULTS_DIR / "single_vs_multi_seed_comparison.csv"
    if df.empty or "seed" not in df.columns:
        out.write_text("", encoding="utf-8")
        return out
    main = df[df["scenario"] != "fpr"].copy()
    if main.empty:
        out.write_text("", encoding="utf-8")
        return out

    pooled = pooled_summary(main, success_col="bypass")
    rows: list[dict[str, Any]] = []
    for (scenario, waf), chunk in main.groupby(["scenario", "waf"]):
        single = chunk[chunk["seed"] == baseline_seed]
        if single.empty:
            single_rate = float("nan")
            single_n = 0
            single_bp = 0
        else:
            bp = _ensure_bool(single["bypass"])
            single_n = len(single)
            single_bp = int(bp.sum())
            single_rate = float(single_bp / single_n) if single_n else 0.0
        pooled_row = pooled[(pooled["scenario"] == scenario) & (pooled["waf"] == waf)]
        if pooled_row.empty:
            continue
        pr = pooled_row.iloc[0]
        single_zero = single_rate == 0.0
        pooled_zero = float(pr["rate_pooled"]) == 0.0
        qualitative_change = single_zero != pooled_zero
        rows.append({
            "scenario": str(scenario),
            "waf": str(waf),
            "single_seed_42_bypasses": single_bp,
            "single_seed_42_n": single_n,
            "single_seed_42_rate": round(single_rate, 6),
            "pooled_n_seeds": int(pr["n_seeds"]),
            "pooled_n_attempts": int(pr["n_attempts_total"]),
            "pooled_bypasses": int(pr["successes_total"]),
            "pooled_rate": round(float(pr["rate_pooled"]), 6),
            "pooled_ci95_lo": round(float(pr["ci95_lo"]), 6),
            "pooled_ci95_hi": round(float(pr["ci95_hi"]), 6),
            "pooled_rate_mean_per_seed": round(float(pr["rate_mean_per_seed"]), 6),
            "pooled_rate_std_per_seed": round(float(pr["rate_std_per_seed"]), 6),
            "qualitative_change": qualitative_change,
        })
    pd.DataFrame(rows).to_csv(out, index=False)
    return out


def dump_per_seed_breakdown(df: pd.DataFrame) -> Path:
    """Write a compact per-seed × scenario × waf attempt breakdown to JSON.

    Layout:
      {
        "<seed>": {
          "<scenario>": {
            "<waf>": {
              "n_attempts": int,
              "bypasses": int,
              "bypass_rate": float,
              "attempt_no": [int, int, ...],
              "bypass":     [bool, bool, ...],
              "waf_blocked":[bool, bool, ...]
            }
          }
        }
      }

    Designed so that convergence curves and per-seed timelines for
    this chart can be redrawn from this single artefact
    without re-running the experiments.
    """
    out_path = RESULTS_DIR / "per_seed_breakdown.json"
    if df.empty or "seed" not in df.columns:
        out_path.write_text("{}", encoding="utf-8")
        return out_path
    bundle: dict[str, Any] = {}
    for (seed, scenario, waf), chunk in df.groupby(["seed", "scenario", "waf"]):
        chunk_sorted = chunk.sort_values("attempt_no")
        bp = _ensure_bool(chunk_sorted["bypass"]).astype(bool)
        wb = _ensure_bool(chunk_sorted["waf_blocked"]).astype(bool)
        seed_bucket = bundle.setdefault(str(seed), {})
        scenario_bucket = seed_bucket.setdefault(str(scenario), {})
        scenario_bucket[str(waf)] = {
            "n_attempts": len(chunk_sorted),
            "bypasses": int(bp.sum()),
            "bypass_rate": round(float(bp.sum() / len(chunk_sorted)), 6)
                           if len(chunk_sorted) else 0.0,
            "attempt_no": chunk_sorted["attempt_no"].astype(int).tolist(),
            "bypass": bp.tolist(),
            "waf_blocked": wb.tolist(),
        }
    out_path.write_text(
        json.dumps(bundle, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    return out_path


def write_multi_seed_table(df: pd.DataFrame) -> Path:
    """Compose the multi-seed CSV combining bypass and block rates."""
    main = df[df["scenario"] != "fpr"].copy()
    fpr = df[df["scenario"] == "fpr"].copy()

    bypass = pooled_summary(main, success_col="bypass")
    bypass = bypass.rename(columns={
        "rate_pooled": "bypass_rate", "ci95_lo": "bypass_ci95_lo",
        "ci95_hi": "bypass_ci95_hi", "rate_mean_per_seed": "bypass_rate_mean",
        "rate_std_per_seed": "bypass_rate_std",
    })
    block = pooled_summary(main, success_col="waf_blocked")
    block = block[["scenario", "waf", "rate_pooled",
                   "ci95_lo", "ci95_hi"]].rename(columns={
        "rate_pooled": "block_rate", "ci95_lo": "block_ci95_lo",
        "ci95_hi": "block_ci95_hi",
    })
    merged_main = bypass.merge(block, on=["scenario", "waf"], how="left")

    if not fpr.empty:
        fpr_block = pooled_summary(fpr, group_cols=("waf",), success_col="waf_blocked")
        fpr_block = fpr_block.rename(columns={
            "rate_pooled": "block_rate", "ci95_lo": "block_ci95_lo",
            "ci95_hi": "block_ci95_hi", "rate_mean_per_seed": "block_rate_mean",
            "rate_std_per_seed": "block_rate_std",
        })
        fpr_block.insert(0, "scenario", "fpr")
    else:
        fpr_block = pd.DataFrame()

    out_path = RESULTS_DIR / "summary_multi_seed.csv"
    if not merged_main.empty or not fpr_block.empty:
        full = pd.concat([merged_main, fpr_block], ignore_index=True, sort=False)
        full.to_csv(out_path, index=False)
    return out_path


_SCENARIO_ORDER = ("s1_baseline", "s2_single_layer", "s3_multi_layer", "s4_adaptive")


def chart_bypass_rate_by_scenario(df: pd.DataFrame) -> Path:
    """Bar chart: 4 scenarios × 3 WAFs with Wilson CI95 error bars (multi-seed)."""
    out = CHARTS_DIR / "bypass_rate_by_scenario.png"
    main = df[df["scenario"] != "fpr"].copy()
    if main.empty:
        return out
    summary = pooled_summary(main, success_col="bypass")
    if summary.empty:
        return out
    pivot_rate = summary.pivot(
        index="scenario", columns="waf", values="rate_pooled"
    )
    pivot_lo = summary.pivot(index="scenario", columns="waf", values="ci95_lo")
    pivot_hi = summary.pivot(index="scenario", columns="waf", values="ci95_hi")
    order = [s for s in _SCENARIO_ORDER if s in pivot_rate.index]
    pivot_rate = pivot_rate.loc[order]
    pivot_lo = pivot_lo.loc[order]
    pivot_hi = pivot_hi.loc[order]

    fig, ax = plt.subplots(figsize=(12, 6))
    pivot_rate.plot(kind="bar", ax=ax, edgecolor="black", capsize=4)
    # Add CI95 error bars manually (matplotlib's bar.errorbar via DataFrame.plot
    # passes one-sided yerr only; we want two-sided from Wilson CI directly).
    waf_cols = list(pivot_rate.columns)
    n_groups = len(pivot_rate.index)
    n_wafs = len(waf_cols)
    width = 0.8 / n_wafs
    for j, waf in enumerate(waf_cols):
        for i, scenario in enumerate(pivot_rate.index):
            rate = float(pivot_rate.loc[scenario, waf])
            lo = float(pivot_lo.loc[scenario, waf])
            hi = float(pivot_hi.loc[scenario, waf])
            x = i - 0.4 + width * (j + 0.5)
            ax.errorbar(
                [x], [rate],
                yerr=[[max(0.0, rate - lo)], [max(0.0, hi - rate)]],
                fmt="none", ecolor="black", elinewidth=1.0, capsize=3, alpha=0.7,
            )
    n_seeds = int(summary["n_seeds"].max()) if "n_seeds" in summary else 1
    ax.set_title(
        f"AMHF — bypass rate by scenario × WAF (Flag-app, {n_seeds} seeds, 95% CI)"
    )
    ax.set_ylabel("bypass rate")
    ax.set_xlabel("scenario")
    ax.set_ylim(0.0, max(0.05, float(pivot_hi.values.max()) * 1.2))
    ax.legend(title="WAF", loc="upper left")
    ax.grid(axis="y", alpha=0.3)
    plt.xticks(rotation=20, ha="right")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    _ = n_groups  # silence unused-name accountancy
    return out


def chart_convergence(df: pd.DataFrame, waf: str) -> Path | None:
    """Rolling-window bypass rate (window=100) for S3 vs S4 on a given WAF."""
    sub = df[(df["scenario"].isin(("s3_multi_layer", "s4_adaptive")))
             & (df["waf"] == waf)].copy()
    if sub.empty:
        return None
    sub["bypass"] = _ensure_bool(sub["bypass"]).astype(int)
    fig, ax = plt.subplots(figsize=(12, 5))
    for scenario, color, style in (
        ("s3_multi_layer", "tab:blue", "--"),
        ("s4_adaptive",   "tab:orange", "-"),
    ):
        chunk = sub[sub["scenario"] == scenario].sort_values("attempt_no")
        if chunk.empty:
            continue
        rolling = chunk["bypass"].rolling(window=100, min_periods=10).mean()
        ax.plot(chunk["attempt_no"].to_numpy(), rolling.to_numpy(),
                label=scenario, color=color, linestyle=style, linewidth=1.5)
    ax.set_title(f"AMHF — rolling bypass rate (window=100), WAF: {waf}")
    ax.set_xlabel("attempt number")
    ax.set_ylabel("rolling bypass rate")
    ax.set_ylim(0.0, 1.0)
    ax.legend(loc="upper left")
    ax.grid(alpha=0.3)
    out = CHARTS_DIR / f"convergence_{waf}.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_time_to_first_bypass(df: pd.DataFrame) -> Path:
    """Boxplot of time_to_first_bypass per scenario × WAF."""
    main = df[df["scenario"] != "fpr"].copy()
    if main.empty:
        return CHARTS_DIR / "time_to_first_bypass.png"
    rows: list[dict[str, Any]] = []
    for (scenario, waf), chunk in main.groupby(["scenario", "waf"]):
        chunk_sorted = chunk.sort_values("attempt_no")
        bp = _ensure_bool(chunk_sorted["bypass"])
        first_idx = bp.idxmax() if bp.any() else None
        if first_idx is not None and bp.loc[first_idx]:
            ttfb = int(str(chunk_sorted.loc[first_idx, "attempt_no"]))
        else:
            ttfb = None
        rows.append({"scenario": scenario, "waf": waf, "ttfb": ttfb})
    ttfb_df = pd.DataFrame(rows)
    fig, ax = plt.subplots(figsize=(11, 6))
    ttfb_df_clean = ttfb_df.dropna(subset=["ttfb"])
    if not ttfb_df_clean.empty:
        ttfb_df_clean.boxplot(column="ttfb", by="scenario", ax=ax, grid=False)
    ax.set_title("AMHF — time to first bypass by scenario")
    ax.set_xlabel("scenario")
    ax.set_ylabel("attempt number of first bypass")
    plt.suptitle("")
    plt.xticks(rotation=20, ha="right")
    out = CHARTS_DIR / "time_to_first_bypass.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_fpr_legitimate(df: pd.DataFrame) -> Path:
    """FPR per WAF on legitimate traffic with Wilson CI95 error bars."""
    out = CHARTS_DIR / "fpr_legitimate_traffic.png"
    fpr = df[df["scenario"] == "fpr"].copy()
    if fpr.empty:
        return out
    summary = pooled_summary(fpr, group_cols=("waf",), success_col="waf_blocked")
    if summary.empty:
        return out
    fig, ax = plt.subplots(figsize=(8, 5))
    waf_labels = summary["waf"].astype(str).tolist()
    rates = summary["rate_pooled"].astype(float).to_numpy()
    yerr_lo = (summary["rate_pooled"] - summary["ci95_lo"]).clip(lower=0.0).to_numpy()
    yerr_hi = (summary["ci95_hi"] - summary["rate_pooled"]).clip(lower=0.0).to_numpy()
    ax.bar(waf_labels, rates, edgecolor="black", color="tab:red",
           yerr=[yerr_lo, yerr_hi], capsize=5)
    n_seeds = int(summary["n_seeds"].max()) if "n_seeds" in summary else 1
    ax.set_title(
        f"AMHF — FPR on legitimate traffic ({n_seeds} seeds, 95% CI)"
    )
    ax.set_xlabel("WAF")
    ax.set_ylabel("WAF-block rate on benign traffic (false positive rate)")
    ax.set_ylim(0.0, max(0.05, float(summary["ci95_hi"].max()) * 1.2))
    for i, (_label, y) in enumerate(zip(waf_labels, rates, strict=True)):
        ax.text(float(i), float(y) + 0.005, f"{y:.3f}", ha="center", fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_bypass_rate_distribution(df: pd.DataFrame) -> Path:
    """Per-seed bypass-rate boxplot — multi-seed visualization."""
    out = CHARTS_DIR / "bypass_rate_distribution.png"
    main = df[df["scenario"] != "fpr"].copy()
    if main.empty:
        return out
    per_seed = per_seed_rates(main, success_col="bypass")
    if per_seed.empty or per_seed["seed"].nunique() < 2:
        # Single-seed case — boxplot is degenerate. Still emit a placeholder
        # bar plot of per-seed rates to keep the artefact set complete.
        fig, ax = plt.subplots(figsize=(11, 6))
        per_seed.set_index("scenario")["rate"].plot(kind="bar", ax=ax)
        ax.set_title("AMHF — per-seed bypass rate (insufficient seeds for boxplot)")
        ax.set_ylabel("bypass rate")
        plt.xticks(rotation=20, ha="right")
        fig.savefig(out, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return out
    waf_order = sorted(per_seed["waf"].unique())
    sce_order = [s for s in _SCENARIO_ORDER if s in per_seed["scenario"].unique()]
    fig, axes = plt.subplots(
        1, len(waf_order), figsize=(5 * len(waf_order), 6), sharey=True,
    )
    if len(waf_order) == 1:
        axes = [axes]
    for ax, waf in zip(axes, waf_order, strict=True):
        sub = per_seed[per_seed["waf"] == waf]
        data = [sub[sub["scenario"] == s]["rate"].to_numpy() for s in sce_order]
        ax.boxplot(data, tick_labels=sce_order, showmeans=True)
        ax.set_title(f"WAF: {waf}")
        ax.set_xlabel("scenario")
        ax.tick_params(axis="x", rotation=20)
        ax.grid(axis="y", alpha=0.3)
    axes[0].set_ylabel("per-seed bypass rate")
    n_seeds = int(per_seed["seed"].nunique())
    fig.suptitle(
        f"AMHF — per-seed bypass-rate distribution across {n_seeds} seeds",
    )
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


def write_summary_table(df: pd.DataFrame) -> Path:
    """Aggregate bypass-rate / block-rate / FPR / TTFB into a flat CSV."""
    rows: list[dict[str, Any]] = []
    for (scenario, waf, backend), chunk in df.groupby(
        ["scenario", "waf", "backend"]
    ):
        bp = _ensure_bool(chunk["bypass"])
        wb = _ensure_bool(chunk["waf_blocked"])
        ttfb = None
        if bp.any():
            sorted_chunk = chunk.sort_values("attempt_no")
            sorted_bp = _ensure_bool(sorted_chunk["bypass"])
            first_idx = sorted_bp.idxmax()
            ttfb = int(str(sorted_chunk.loc[first_idx, "attempt_no"]))
        rows.append({
            "scenario": scenario,
            "waf": waf,
            "backend": backend,
            "n_attempts": len(chunk),
            "bypasses": int(bp.sum()),
            "bypass_rate": round(float(bp.sum() / len(chunk)), 4),
            "blocks": int(wb.sum()),
            "block_rate": round(float(wb.sum() / len(chunk)), 4),
            "time_to_first_bypass": ttfb,
        })
    out = RESULTS_DIR / "summary_table.csv"
    pd.DataFrame(rows).to_csv(out, index=False)
    return out


def main() -> int:
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    print("collecting runs from results/...")
    df = _gather_runs()
    if df.empty:
        print("no run-* directories found; nothing to aggregate")
        return 1
    n_seeds = int(df["seed"].nunique()) if "seed" in df.columns else 1
    print(f"\ntotal attempts loaded: {len(df)} (across {n_seeds} distinct seeds)")
    print(f"runs by (scenario, waf):\n{df.groupby(['scenario', 'waf']).size()}\n")

    summary_path = write_summary_table(df)
    print(f"  -> {summary_path}")
    multi_path = write_multi_seed_table(df)
    print(f"  -> {multi_path}")
    comparison_path = write_single_vs_multi_seed_comparison(df)
    print(f"  -> {comparison_path}")
    breakdown_path = dump_per_seed_breakdown(df)
    print(f"  -> {breakdown_path}")
    bp_chart = chart_bypass_rate_by_scenario(df)
    print(f"  -> {bp_chart}")
    for waf in df[df["scenario"] != "fpr"]["waf"].unique():
        out = chart_convergence(df, waf)
        if out is not None:
            print(f"  -> {out}")
    ttfb = chart_time_to_first_bypass(df)
    print(f"  -> {ttfb}")
    fpr = chart_fpr_legitimate(df)
    print(f"  -> {fpr}")
    dist = chart_bypass_rate_distribution(df)
    print(f"  -> {dist}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
