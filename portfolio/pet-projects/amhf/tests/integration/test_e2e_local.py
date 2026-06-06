"""End-to-end integration test for AMHF Stage 3.

Brings up a single in-process aiohttp app that plays BOTH the WAF and the
vulnerable backend simultaneously, then drives it through the full
delivery -> oracle -> storage chain. This is the
proof-of-life: a real chromosome of mutated bytes flows from the client
to the server, the response is classified by the dual oracle, and the
bypass verdict is durably persisted into both CSV and SQLite sinks.

The mock app intentionally implements a *naive* WAF that only inspects
the raw (un-decoded) URL — that is the same mistake real WAFs make and
the reason percent-encoded payloads slip past. The backend then
URL-decodes its own input, mirroring DVWA / Flag-app behaviour.
"""

from __future__ import annotations

import asyncio
import time
import urllib.parse
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer

from amhf.config import (
    BackendOracleConfig,
    CmdiOracleConfig,
    OracleConfig,
    PathTravOracleConfig,
    SqliOracleConfig,
    WafOracleConfig,
    XssOracleConfig,
)
from amhf.delivery import AsyncHTTPClient, FuzzRequest
from amhf.oracle import (
    CombinedOracle,
    OracleReason,
    OracleVerdict,
    TimingOracle,
    WafOracle,
)
from amhf.storage import AttemptKind, AttemptRecord, CSVSink, SQLiteSink

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


# --------------------------------------------------------------------------
# Mock server: WAF + backend in one aiohttp app.
# --------------------------------------------------------------------------


_BLOCK_BODY_SQLI = "<html>ModSecurity blocked your request</html>"
_BLOCK_BODY_CMDI = "<html>ModSecurity Access Denied (CMDi pattern)</html>"
_BLOCK_BODY_LFI = "<html>ModSecurity Access Denied (LFI pattern)</html>"


# --------------------------------------------------------------------------
# WAF / backend decode model
# --------------------------------------------------------------------------
# HTTP clients (browsers, aiohttp, ...) percent-encode special characters
# on the wire automatically. The mock therefore models a realistic
# *double-decode* asymmetry:
#
#   1. aiohttp.web does the standard one-pass percent-decode of the query
#      string before handing values to the handler — that decoded form is
#      what the WAF inspects (this is what real WAFs see, post-parse).
#   2. The application code then does a *second* decode on its own input
#      (a common bug in DVWA-style apps that re-decode user input as JSON
#      or form data) — that is the "backend view".
#
# A payload that is double-percent-encoded (e.g. ``%253Cscript%253E`` for
# ``<script>``) decodes ONCE to the harmless ``%3Cscript%3E`` for the WAF
# but TWICE to the executable ``<script>`` for the backend → bypass.


def _waf_view(value_decoded_once: str) -> str:
    """The form the WAF sees after the HTTP server's standard decode."""
    return value_decoded_once


def _backend_view(value_decoded_once: str) -> str:
    """The form the backend sees after its second URL-decode pass."""
    return urllib.parse.unquote_plus(value_decoded_once)


async def _sqli_handler(request: web.Request) -> web.Response:
    once = request.rel_url.query.get("id", "")
    waf_view = _waf_view(once)
    if "' OR '1'='1" in waf_view or "UNION SELECT" in waf_view.upper():
        return web.Response(text=_BLOCK_BODY_SQLI, status=403)
    decoded = _backend_view(once)
    if "'" in decoded or "OR" in decoded.upper():
        body = (
            "<html><body>id=1 leaked secret token: AMHF_FLAG_42 ok</body></html>"
        )
        return web.Response(text=body, status=200)
    return web.Response(text="ok", status=200)


async def _xss_handler(request: web.Request) -> web.Response:
    once = request.rel_url.query.get("q", "")
    waf_view = _waf_view(once)
    if "<script>" in waf_view.lower():
        # Classic WAF-trap: block-page reflects the payload literally.
        body = (
            "<html><body>Forbidden by ModSecurity. "
            f"You sent: {_backend_view(once)}</body></html>"
        )
        return web.Response(text=body, status=403)
    decoded = _backend_view(once)
    body = f"<html><body><div>You searched for: {decoded}</div></body></html>"
    return web.Response(text=body, status=200)


async def _cmdi_handler(request: web.Request) -> web.Response:
    once = request.rel_url.query.get("cmd", "")
    waf_view = _waf_view(once)
    if "; id" in waf_view:
        return web.Response(text=_BLOCK_BODY_CMDI, status=403)
    decoded = _backend_view(once)
    body = f"amhf_cmd_marker {decoded}\n"
    return web.Response(text=body, status=200)


async def _lfi_handler(request: web.Request) -> web.Response:
    once = request.rel_url.query.get("file", "")
    waf_view = _waf_view(once)
    if "../" in waf_view:
        return web.Response(text=_BLOCK_BODY_LFI, status=403)
    decoded = _backend_view(once)
    if decoded == "/etc/amhf_canary":
        return web.Response(text="amhf_canary_v1\n", status=200)
    return web.Response(text="not found\n", status=404)


async def _sleep_handler(request: web.Request) -> web.Response:
    raw_ms = request.rel_url.query.get("ms", "0")
    try:
        ms = max(0, min(int(raw_ms), 5000))
    except ValueError:
        ms = 0
    await asyncio.sleep(ms / 1000.0)
    return web.Response(text=f"slept {ms}ms", status=200)


def make_mock_app() -> web.Application:
    """Build the in-process WAF+backend mock as a single aiohttp app."""
    app = web.Application()
    app.router.add_get("/sqli", _sqli_handler)
    app.router.add_get("/xss", _xss_handler)
    app.router.add_get("/cmdi", _cmdi_handler)
    app.router.add_get("/lfi", _lfi_handler)
    app.router.add_get("/sleep", _sleep_handler)
    return app


# --------------------------------------------------------------------------
# Fixtures.
# --------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def mock_server() -> AsyncIterator[TestServer]:
    """Yield a running TestServer hosting make_mock_app()."""
    srv = TestServer(make_mock_app())
    await srv.start_server()
    try:
        yield srv
    finally:
        await srv.close()


def _url(server: TestServer, path: str) -> str:
    return str(server.make_url(path))


def _make_oracle(timing: TimingOracle | None = None) -> CombinedOracle:
    """Build a CombinedOracle whose defaults mirror configs/default.yaml."""
    cfg = OracleConfig(
        waf=WafOracleConfig(
            blocked_codes=[403, 406, 501, 418, 419],
            blocked_body_signatures=[
                "Access Denied",
                "ModSecurity",
                "Nemesida WAF",
                "NAXSI",
                "Forbidden",
            ],
            block_page_size_max=4096,
        ),
        backend=BackendOracleConfig(
            sqli=SqliOracleConfig(
                error_signatures=[
                    "You have an error in your SQL syntax",
                    "PostgreSQL",
                    "ORA-",
                    "SQLite",
                ],
                flag_marker="AMHF_FLAG_",
                time_delay_threshold_ms=2500.0,
            ),
            xss=XssOracleConfig(reflection_check=True),
            cmdi=CmdiOracleConfig(command_marker="amhf_cmd_marker"),
            pathtrav=PathTravOracleConfig(canary_marker="amhf_canary_v1"),
        ),
    )
    return CombinedOracle(cfg, timing=timing)


def _verdict_to_record(
    verdict: OracleVerdict,
    *,
    run_id: str,
    attempt_no: int,
    target_id: str,
    payload_id: str,
    payload_text: str,
    chromosome: list[str],
    status_code: int,
    response_time_ms: float,
    seed: int,
) -> AttemptRecord:
    """Translate one OracleVerdict into the AttemptRecord schema."""
    return AttemptRecord(
        timestamp=datetime.now(tz=UTC),
        run_id=run_id,
        attempt_no=attempt_no,
        target_id=target_id,
        payload_id=payload_id,
        payload_text=payload_text,
        chromosome=chromosome,
        mutated_request_summary=f"GET {target_id}",
        status_code=status_code,
        response_time_ms=response_time_ms,
        waf_blocked=verdict.waf_blocked,
        waf_signature_hit=verdict.waf_signature_hit,
        exploit_confirmed=verdict.exploit_confirmed,
        oracle_reason=verdict.reason.value,
        bypass=verdict.bypass,
        ucb_reward=1 if verdict.bypass else 0,
        attempt_kind=AttemptKind.MUTATION,
        seed=seed,
    )


# --------------------------------------------------------------------------
# Tests.
# --------------------------------------------------------------------------


async def test_sqli_raw_block(mock_server: TestServer) -> None:
    """Un-encoded `' OR '1'='1` is caught by the WAF (after one HTTP decode
    pass it appears literally in the WAF's view) -> WAF_BLOCKED."""
    oracle = _make_oracle()
    target = _url(mock_server, "/sqli") + "?id=' OR '1'='1"
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(FuzzRequest(method="GET", url=target))

    waf = WafOracle(WafOracleConfig(
        blocked_codes=[403], blocked_body_signatures=["ModSecurity"],
    ))
    blocked, sig = waf.is_blocked(resp)
    assert blocked is True
    assert sig is not None

    verdict = oracle.evaluate(resp, "sqli", payload_text="' OR '1'='1")
    assert verdict.bypass is False
    assert verdict.reason == OracleReason.WAF_BLOCKED
    assert verdict.waf_blocked is True
    assert verdict.exploit_confirmed is False


async def test_sqli_url_encoded_bypass(mock_server: TestServer) -> None:
    """End-to-end proof-of-life: percent-encoded SQLi slips past the WAF,
    the backend URL-decodes it once more (the second decode is the bug),
    and BackendOracle picks up the AMHF_FLAG_42 leak. This is the central
    artefact — a single request's worth of
    evidence that the full chain delivery -> dual oracle -> verdict
    actually works.

    Note on the encoding: HTTP clients (incl. aiohttp) percent-encode
    special chars on the wire automatically, so the on-the-wire form of
    ``' OR '1'='1`` and ``%27%20OR%20%271%27%3D%271`` is identical. To
    model a real WAF-bypass we therefore double-encode: the client sends
    ``%2527%2520OR%2520...``, the HTTP server decodes ONCE so the WAF
    sees ``%27%20OR%20%271%27%3D%271`` (harmless), and the backend
    decodes a SECOND time to recover the executable payload.
    """
    oracle = _make_oracle()
    once_encoded = "%27%20OR%20%271%27%3D%271"  # what the WAF should see
    twice_encoded = once_encoded.replace("%", "%25")
    target = _url(mock_server, "/sqli") + f"?id={twice_encoded}"
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(FuzzRequest(method="GET", url=target))

    assert resp.status_code == 200, f"got {resp.status_code}: {resp.body_text!r}"
    assert "AMHF_FLAG_42" in resp.body_text

    verdict = oracle.evaluate(resp, "sqli", payload_text="' OR '1'='1")
    # Print the verdict so there is a real artefact.
    print(f"\n[E2E proof-of-life verdict]\n  {verdict}\n")
    assert verdict.bypass is True
    assert verdict.reason == OracleReason.EXPLOIT_CONFIRMED
    assert verdict.exploit_confirmed is True
    assert verdict.waf_blocked is False
    assert "AMHF_FLAG_42" in verdict.detail
    assert verdict.server_error is False


async def test_xss_waf_trap_does_not_confirm(mock_server: TestServer) -> None:
    """KEY CORRECTNESS: a 403 block-page that *reflects* the XSS payload
    literally must NOT be confirmed as exploitation — WafOracle wins.

    The raw ``<script>`` is encoded by the HTTP client to ``%3Cscript%3E``,
    the server decodes it ONCE for handler dispatch, the WAF sees the
    plain ``<script>`` and blocks. The block-page intentionally reflects
    the payload literally — exactly the trap that should NOT fool the
    XSS reflection oracle.
    """
    oracle = _make_oracle()
    payload = "<script>alert(1)</script>"
    target = _url(mock_server, "/xss") + "?q=<script>alert(1)</script>"
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(FuzzRequest(method="GET", url=target))

    assert resp.status_code == 403
    # WAF page DID reflect the payload: this is the trap.
    assert payload in resp.body_text

    verdict = oracle.evaluate(resp, "xss", payload_text=payload)
    assert verdict.bypass is False
    assert verdict.reason == OracleReason.WAF_BLOCKED
    assert verdict.exploit_confirmed is False
    assert verdict.waf_blocked is True


async def test_xss_genuine_bypass(mock_server: TestServer) -> None:
    """Double-encoded ``<script>`` bypasses the WAF; backend's second
    URL-decode pass reconstructs the executable payload, which is then
    reflected unescaped in the body. CombinedOracle confirms XSS.

    Same encoding logic as ``test_sqli_url_encoded_bypass``.
    """
    oracle = _make_oracle()
    payload = "<script>alert(1)</script>"
    once_encoded = urllib.parse.quote(payload, safe="")
    twice_encoded = once_encoded.replace("%", "%25")
    target = _url(mock_server, "/xss") + f"?q={twice_encoded}"
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(FuzzRequest(method="GET", url=target))

    assert resp.status_code == 200, f"got {resp.status_code}: {resp.body_text!r}"
    assert payload in resp.body_text

    verdict = oracle.evaluate(resp, "xss", payload_text=payload)
    assert verdict.bypass is True
    assert verdict.reason == OracleReason.EXPLOIT_CONFIRMED
    assert verdict.exploit_confirmed is True
    assert verdict.waf_blocked is False


async def test_cmdi_success(mock_server: TestServer) -> None:
    """Backend echoes `amhf_cmd_marker id` -> BackendOracle confirms CMDi."""
    oracle = _make_oracle()
    target = _url(mock_server, "/cmdi") + "?cmd=id"
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(FuzzRequest(method="GET", url=target))

    assert resp.status_code == 200
    assert "amhf_cmd_marker" in resp.body_text

    verdict = oracle.evaluate(resp, "cmdi", payload_text="id")
    assert verdict.bypass is True
    assert verdict.reason == OracleReason.EXPLOIT_CONFIRMED
    assert verdict.detail == "cmd-marker"


async def test_pathtrav_success(mock_server: TestServer) -> None:
    """Backend reads /etc/amhf_canary and reveals canary content -> bypass."""
    oracle = _make_oracle()
    encoded_path = urllib.parse.quote("/etc/amhf_canary", safe="")
    target = _url(mock_server, "/lfi") + f"?file={encoded_path}"
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(FuzzRequest(method="GET", url=target))

    assert resp.status_code == 200
    assert "amhf_canary_v1" in resp.body_text

    verdict = oracle.evaluate(resp, "pathtrav", payload_text="/etc/amhf_canary")
    assert verdict.bypass is True
    assert verdict.reason == OracleReason.EXPLOIT_CONFIRMED
    assert verdict.detail == "canary-marker"


async def test_time_based_blind_sqli(mock_server: TestServer) -> None:
    """Time-based blind SQLi: TimingOracle threshold 2000 ms, server
    sleeps 3500 ms. CombinedOracle (with the timing oracle injected)
    must classify this as EXPLOIT_CONFIRMED via the __TIME_DELAY__
    pseudo-marker channel.
    """
    timing = TimingOracle.from_threshold(2000.0)
    oracle = _make_oracle(timing=timing)
    target = _url(mock_server, "/sleep") + "?ms=3500"

    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=10.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(FuzzRequest(method="GET", url=target))

    assert resp.status_code == 200
    assert resp.error is None
    assert resp.elapsed_ms >= 2000.0, f"expected delay, got {resp.elapsed_ms:.0f}ms"
    assert timing.is_delayed(resp.elapsed_ms) is True

    # Pass __TIME_DELAY__ pseudo-marker so BackendOracle.check_sqli
    # routes through the timing channel.
    verdict = oracle.evaluate(
        resp,
        "sqli",
        payload_text="' AND SLEEP(3) -- ",
        expected_markers=("__TIME_DELAY__",),
    )
    assert verdict.bypass is True
    assert verdict.reason == OracleReason.EXPLOIT_CONFIRMED
    assert verdict.exploit_confirmed is True
    assert "timing-blind" in verdict.detail


async def test_storage_round_trip(
    mock_server: TestServer, tmp_path: Path,
) -> None:
    """Run a real bypass through delivery+oracle, persist the verdict
    into both CSVSink and SQLiteSink, then re-open and verify the row
    count and key fields. Validates the oracle -> storage seam."""
    oracle = _make_oracle()
    once_encoded = "%27%20OR%20%271%27%3D%271"
    twice_encoded = once_encoded.replace("%", "%25")
    target = _url(mock_server, "/sqli") + f"?id={twice_encoded}"

    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(FuzzRequest(method="GET", url=target))
    verdict = oracle.evaluate(resp, "sqli", payload_text="' OR '1'='1")
    assert verdict.bypass is True

    record = _verdict_to_record(
        verdict,
        run_id="run-e2e-001",
        attempt_no=1,
        target_id=target,
        payload_id="sqli_taut_001",
        payload_text="' OR '1'='1",
        chromosome=["url_encode"],
        status_code=resp.status_code,
        response_time_ms=resp.elapsed_ms,
        seed=42,
    )

    csv_sink = CSVSink(tmp_path)
    sqlite_sink = SQLiteSink(tmp_path)
    csv_sink.open("run-e2e-001")
    sqlite_sink.open("run-e2e-001")
    try:
        csv_sink.write(record)
        sqlite_sink.write(record)
    finally:
        csv_sink.close()
        sqlite_sink.close()

    # Verify CSV: header + 1 row.
    csv_path = tmp_path / "attempts.csv"
    assert csv_path.exists()
    csv_lines = csv_path.read_text(encoding="utf-8").splitlines()
    assert len(csv_lines) == 2  # header + 1 record
    assert "run-e2e-001" in csv_lines[1]
    assert "true" in csv_lines[1]  # bypass=True serialised as "true"

    # Verify SQLite: one row, fields round-trip correctly.
    import sqlite3
    sqlite_path = tmp_path / "attempts.sqlite3"
    assert sqlite_path.exists()
    conn = sqlite3.connect(sqlite_path)
    try:
        cur = conn.execute(
            "SELECT run_id, attempt_no, bypass, oracle_reason FROM attempts"
        )
        rows = cur.fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    run_id, attempt_no, bypass, reason = rows[0]
    assert run_id == "run-e2e-001"
    assert attempt_no == 1
    assert bypass == 1
    assert reason == OracleReason.EXPLOIT_CONFIRMED.value


async def test_concurrency_smoke(mock_server: TestServer) -> None:
    """30 parallel /sleep?ms=50 requests at concurrency=10 must complete
    in well under 1 s — confirms AsyncHTTPClient parallelises properly
    when wired into a real aiohttp handler."""
    target = _url(mock_server, "/sleep") + "?ms=50"
    async with AsyncHTTPClient(
        concurrency=10, request_timeout_s=5.0, rate_limit_rps=10_000.0,
    ) as client:
        started = time.perf_counter()
        results = await asyncio.gather(
            *(client.send(FuzzRequest(method="GET", url=target)) for _ in range(30))
        )
        elapsed = time.perf_counter() - started

    assert all(r.status_code == 200 for r in results)
    assert len(results) == 30
    # Theoretical: ceil(30/10) * 50ms = 150 ms. Allow 1 s safety margin.
    print(f"\n[Concurrency-smoke] 30 reqs, conc=10, ms=50 -> elapsed={elapsed:.3f}s\n")
    assert elapsed < 1.0, f"concurrency-smoke took {elapsed:.3f}s (expected < 1.0s)"
