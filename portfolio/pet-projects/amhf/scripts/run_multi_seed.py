"""Multi-seed wrapper around scripts/run_experiments.py.

Each seed runs in a clean stand: ``docker compose down -v`` then ``up -d``,
poll readiness, then ``run_experiments.py --seed N``. Default seeds are
the canonical {42, 137, 256, 1024, 2026}; override via
``--seeds 1,2,3``. The accumulated ``results/run-*`` directories are
labelled by the orchestrator's timestamp suffix, but each AttemptRecord
also carries its ``seed`` field so the multi-seed aggregator can group.

Usage::

    python scripts/run_multi_seed.py
    python scripts/run_multi_seed.py --seeds 42,137 --total 500   # smaller dry-run
"""

from __future__ import annotations

import argparse
import contextlib
import shlex
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

DEFAULT_SEEDS = (42, 137, 256, 1024, 2026)
DEFAULT_TOTAL = 2000
COMPOSE_FILE = Path("stand") / "docker-compose.yml"
HEALTH_PORTS = (8080, 8081, 8083, 8090, 8091, 8093)
HEALTH_TIMEOUT_S = 90


def _docker(*args: str, capture: bool = False) -> str:
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), *args]
    print(f"  $ {shlex.join(cmd)}")
    if capture:
        return subprocess.check_output(cmd, text=True, encoding="utf-8")
    subprocess.check_call(cmd)
    return ""


def _wait_healthy(timeout_s: int = HEALTH_TIMEOUT_S) -> None:
    """Poll the published WAF ports until each returns < 500."""
    deadline = time.monotonic() + timeout_s
    healthy: set[int] = set()
    while time.monotonic() < deadline:
        for port in HEALTH_PORTS:
            if port in healthy:
                continue
            try:
                with urllib.request.urlopen(
                    f"http://localhost:{port}/healthz",
                    timeout=2,
                ) as resp:
                    if resp.status < 500:
                        healthy.add(port)
            except Exception:  # any transport / 4xx / connection refused
                pass
            # NAXSI on 8081/8091 returns 404 on /healthz but the listener is up.
            if port in (8081, 8091) and port not in healthy:
                try:
                    with urllib.request.urlopen(
                        f"http://localhost:{port}/", timeout=2
                    ) as resp:
                        if resp.status < 500:
                            healthy.add(port)
                except Exception:
                    pass
        if len(healthy) == len(HEALTH_PORTS):
            return
        time.sleep(2.0)
    missing = sorted(set(HEALTH_PORTS) - healthy)
    raise TimeoutError(f"WAF ports did not become healthy in {timeout_s}s: {missing}")


def _run_seed(seed: int, total: int, python: str) -> int:
    cmd = [
        python, "scripts/run_experiments.py",
        "--seed", str(seed),
        "--total", str(total),
    ]
    print(f"  $ {shlex.join(cmd)}")
    return subprocess.call(cmd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seeds", type=str,
        default=",".join(str(s) for s in DEFAULT_SEEDS),
        help=f"comma-separated seeds (default: {DEFAULT_SEEDS})",
    )
    parser.add_argument("--total", type=int, default=DEFAULT_TOTAL,
                        help="total_requests per main scenario (FPR scales by 10%%)")
    parser.add_argument("--python", default=sys.executable,
                        help="python interpreter to invoke run_experiments with")
    parser.add_argument("--keep-up", action="store_true",
                        help="leave the stand running after the last seed")
    args = parser.parse_args()

    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    if not seeds:
        print("no seeds specified")
        return 2

    overall_started = time.monotonic()
    failures: list[int] = []
    for idx, seed in enumerate(seeds, start=1):
        print("\n========================================")
        print(f"=== seed {seed} ({idx}/{len(seeds)})")
        print("========================================")
        seed_started = time.monotonic()
        # Stand reset — clean DVWA DB volume, fresh containers.
        _docker("down", "-v")
        _docker("up", "-d", "--build")
        try:
            _wait_healthy()
        except TimeoutError as exc:
            print(f"  STAND-NOT-HEALTHY: {exc}")
            failures.append(seed)
            continue
        rc = _run_seed(seed, args.total, args.python)
        if rc != 0:
            print(f"  seed {seed}: run_experiments exited {rc}")
            failures.append(seed)
        seed_elapsed = time.monotonic() - seed_started
        print(f"  seed {seed} done in {seed_elapsed:.1f}s")

    if not args.keep_up:
        with contextlib.suppress(subprocess.CalledProcessError):
            _docker("down")

    total_elapsed = time.monotonic() - overall_started
    print(f"\n=== multi-seed done in {total_elapsed:.1f}s "
          f"({len(seeds) - len(failures)}/{len(seeds)} seeds OK) ===")
    if failures:
        print(f"FAILED seeds: {failures}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
