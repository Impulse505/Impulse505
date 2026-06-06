"""AMHF Stage-5 smoke validator for the Docker stand.

Verifies, end-to-end:
  1. Readiness  — every host port answers (status < 500) within ~90 s.
  2. Corpus     — corpus/{sqli,xss,cmdi,pathtrav}.yaml load via Corpus,
                  total == 264 (80/80/51/53).
  3. Benign     — benign GETs return 2xx through every active WAF.
  4. Malicious  — raw textbook attacks are blocked (403/406/501/...).
  5. Markers    — direct (intra-network) hits to flag-app return the
                  literal markers AMHF_FLAG_, amhf_cmd_marker, amhf_canary_v1.

Exit 0 only if every row is OK. Exit 1 with a rich.Table on any failure.

Run:  python scripts/smoke_stand.py

This is a manual artefact, NOT part of pytest. mypy --strict friendly.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import aiohttp
from rich.console import Console
from rich.table import Table

from amhf.corpus import Corpus

# ---------------------------------------------------------------------------- #
# Configuration constants                                                       #
# ---------------------------------------------------------------------------- #

HOST: Final[str] = "http://localhost"
PORTS_DVWA: Final[dict[str, int]] = {"modsec": 8080, "naxsi": 8081}
PORTS_FLAG: Final[dict[str, int]] = {"modsec": 8090, "naxsi": 8091}
# Nemesida ports if/when enabled.
PORTS_NEMESIDA: Final[dict[str, int]] = {"dvwa": 8082, "flag": 8092}

CORPUS_DIR: Final[Path] = Path("corpus")
EXPECTED_PER_CLASS: Final[dict[str, int]] = {
    "sqli": 80,
    "xss": 80,
    "cmdi": 51,
    "pathtrav": 53,
}
EXPECTED_TOTAL: Final[int] = sum(EXPECTED_PER_CLASS.values())  # 264

READY_TIMEOUT_S: Final[float] = 90.0
PER_REQUEST_TIMEOUT_S: Final[float] = 5.0

# Raw textbook attacks. Every WAF should block at least one of (modsec, naxsi).
SQLI_RAW: Final[str] = "' OR '1'='1"
XSS_RAW: Final[str] = "<script>alert(1)</script>"

# Block status codes that any of our WAFs may emit.
BLOCK_CODES: Final[frozenset[int]] = frozenset({403, 406, 418, 419, 501})

console = Console()


# ---------------------------------------------------------------------------- #
# Result type                                                                   #
# ---------------------------------------------------------------------------- #


@dataclass(slots=True)
class Row:
    section: str
    target: str
    expected: str
    actual: str
    ok: bool


def _row(section: str, target: str, expected: str, actual: str, ok: bool) -> Row:
    return Row(section=section, target=target, expected=expected, actual=actual, ok=ok)


# ---------------------------------------------------------------------------- #
# 1. Readiness                                                                  #
# ---------------------------------------------------------------------------- #


async def _wait_ready(
    session: aiohttp.ClientSession, urls: list[str]
) -> list[Row]:
    """Poll each URL until status < 500 or the timeout elapses."""
    rows: list[Row] = []
    deadline = asyncio.get_event_loop().time() + READY_TIMEOUT_S
    pending = set(urls)
    last_status: dict[str, str] = dict.fromkeys(urls, "no-response")
    while pending and asyncio.get_event_loop().time() < deadline:
        for url in list(pending):
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    last_status[url] = str(resp.status)
                    if resp.status < 500:
                        pending.discard(url)
            except aiohttp.ClientError as exc:
                last_status[url] = f"client-error: {type(exc).__name__}"
            except TimeoutError:
                last_status[url] = "timeout"
        if pending:
            await asyncio.sleep(2.0)
    for url in urls:
        ok = url not in pending
        rows.append(
            _row(
                section="readiness",
                target=url,
                expected="status<500",
                actual=last_status[url],
                ok=ok,
            )
        )
    return rows


# ---------------------------------------------------------------------------- #
# 2. Corpus sanity                                                              #
# ---------------------------------------------------------------------------- #


def _check_corpus() -> list[Row]:
    rows: list[Row] = []
    paths = [CORPUS_DIR / f"{cls}.yaml" for cls in EXPECTED_PER_CLASS]
    try:
        corpus = Corpus.from_yaml_paths(paths)
    except (OSError, ValueError) as exc:
        rows.append(
            _row(
                section="corpus",
                target=str(CORPUS_DIR),
                expected=f"loadable, total={EXPECTED_TOTAL}",
                actual=f"error: {exc}",
                ok=False,
            )
        )
        return rows
    rows.append(
        _row(
            section="corpus",
            target=str(CORPUS_DIR),
            expected=f"total={EXPECTED_TOTAL}",
            actual=f"total={len(corpus)}",
            ok=len(corpus) == EXPECTED_TOTAL,
        )
    )
    for cls, expected_n in EXPECTED_PER_CLASS.items():
        actual_n = len(corpus.by_class(cls))
        rows.append(
            _row(
                section="corpus",
                target=cls,
                expected=str(expected_n),
                actual=str(actual_n),
                ok=actual_n == expected_n,
            )
        )
    return rows


# ---------------------------------------------------------------------------- #
# 3 + 4. Benign / malicious traffic                                              #
# ---------------------------------------------------------------------------- #


async def _get(
    session: aiohttp.ClientSession, url: str
) -> tuple[int, str]:
    try:
        async with session.get(url, allow_redirects=False) as resp:
            text = await resp.text(errors="replace")
            return resp.status, text
    except aiohttp.ClientError as exc:
        return -1, f"client-error: {type(exc).__name__}"
    except TimeoutError:
        return -1, "timeout"


async def _check_benign(session: aiohttp.ClientSession) -> list[Row]:
    rows: list[Row] = []
    # ModSec/NAXSI in front of Flag-app: GET /sqli?id=1 should be 200 ok.
    for waf, port in PORTS_FLAG.items():
        url = f"{HOST}:{port}/sqli?id=1"
        status, _ = await _get(session, url)
        rows.append(
            _row(
                section="benign-flag",
                target=f"{waf}->flag /sqli?id=1",
                expected="2xx",
                actual=str(status),
                ok=200 <= status < 300,
            )
        )
    # ModSec/NAXSI in front of DVWA: GET / (login page) should be 200/302.
    for waf, port in PORTS_DVWA.items():
        url = f"{HOST}:{port}/login.php"
        status, _ = await _get(session, url)
        rows.append(
            _row(
                section="benign-dvwa",
                target=f"{waf}->dvwa /login.php",
                expected="2xx/3xx",
                actual=str(status),
                ok=200 <= status < 400,
            )
        )
    return rows


async def _check_malicious(session: aiohttp.ClientSession) -> list[Row]:
    rows: list[Row] = []
    sqli_q = urllib.parse.quote_plus(SQLI_RAW)
    xss_q = urllib.parse.quote_plus(XSS_RAW)
    # Flag-app endpoints — use /sqli and /xss.
    for waf, port in PORTS_FLAG.items():
        for label, q in (("sqli", sqli_q), ("xss", xss_q)):
            param = "id" if label == "sqli" else "q"
            url = f"{HOST}:{port}/{label}?{param}={q}"
            status, _ = await _get(session, url)
            rows.append(
                _row(
                    section="malicious-flag",
                    target=f"{waf}->flag /{label}",
                    expected=f"blocked ({sorted(BLOCK_CODES)})",
                    actual=str(status),
                    ok=status in BLOCK_CODES,
                )
            )
    # DVWA endpoints — DVWA's own SQLi page is at /vulnerabilities/sqli/ but
    # behind login. For a smoke check we just hit the root with a malicious
    # query string, which exercises the WAF identically.
    for waf, port in PORTS_DVWA.items():
        for label, q in (("sqli", sqli_q), ("xss", xss_q)):
            url = f"{HOST}:{port}/?id={q}" if label == "sqli" else f"{HOST}:{port}/?q={q}"
            status, _ = await _get(session, url)
            rows.append(
                _row(
                    section="malicious-dvwa",
                    target=f"{waf}->dvwa /?{label}",
                    expected=f"blocked ({sorted(BLOCK_CODES)})",
                    actual=str(status),
                    ok=status in BLOCK_CODES,
                )
            )
    return rows


# ---------------------------------------------------------------------------- #
# 5. Marker verification (docker exec into flag-app)                            #
# ---------------------------------------------------------------------------- #


def _docker_exec_curl(path: str) -> tuple[int, str]:
    """Call curl from inside amhf-flag-app to bypass the WAFs entirely."""
    argv: list[str] = [
        "docker", "exec", "amhf-flag-app",
        "curl", "-fsS", f"http://localhost:5000{path}",
    ]
    try:
        completed = subprocess.run(
            argv, capture_output=True, timeout=10, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return -1, f"docker-exec-error: {exc}"
    return completed.returncode, completed.stdout.decode("utf-8", errors="replace")


def _check_markers() -> list[Row]:
    rows: list[Row] = []
    # SQLi tautology, double-encoded so the literal ' OR '1'='1 reaches /sqli
    # via Flask's single-decode + the app's second urllib.unquote_plus.
    sqli_dbl = urllib.parse.quote(urllib.parse.quote_plus(SQLI_RAW), safe="")
    cases: list[tuple[str, str, str]] = [
        ("sqli /sqli", f"/sqli?id={sqli_dbl}", "AMHF_FLAG_"),
        ("cmdi /cmdi", "/cmdi?cmd=hello", "amhf_cmd_marker"),
        ("lfi  /lfi",  "/lfi?file=/etc/amhf_canary", "amhf_canary_v1"),
    ]
    for label, path, marker in cases:
        rc, body = _docker_exec_curl(path)
        ok = rc == 0 and marker in body
        rows.append(
            _row(
                section="markers",
                target=label,
                expected=f"contains {marker!r}",
                actual=f"rc={rc} body[:80]={body[:80]!r}",
                ok=ok,
            )
        )
    return rows


# ---------------------------------------------------------------------------- #
# Driver                                                                        #
# ---------------------------------------------------------------------------- #


async def _main_async() -> int:
    timeout = aiohttp.ClientTimeout(total=PER_REQUEST_TIMEOUT_S)
    rows: list[Row] = []
    async with aiohttp.ClientSession(timeout=timeout) as session:
        ready_urls = (
            [f"{HOST}:{p}/login.php" for p in PORTS_DVWA.values()]
            + [f"{HOST}:{p}/healthz" for p in PORTS_FLAG.values()]
        )
        rows.extend(await _wait_ready(session, ready_urls))
        rows.extend(_check_corpus())
        rows.extend(await _check_benign(session))
        rows.extend(await _check_malicious(session))
    rows.extend(_check_markers())

    table = Table(title="AMHF stand smoke test")
    table.add_column("section")
    table.add_column("target")
    table.add_column("expected")
    table.add_column("actual")
    table.add_column("ok", justify="center")
    failures = 0
    for r in rows:
        if not r.ok:
            failures += 1
        table.add_row(
            r.section,
            r.target,
            r.expected,
            r.actual,
            "OK" if r.ok else "FAIL",
            style=None if r.ok else "red",
        )
    console.print(table)
    if failures:
        console.print(f"[red]FAIL[/red]: {failures} row(s) failed")
        return 1
    console.print("[green]OK[/green]: all rows passed")
    return 0


def main() -> int:
    try:
        return asyncio.run(_main_async())
    except KeyboardInterrupt:
        console.print("[yellow]interrupted[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
