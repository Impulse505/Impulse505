"""AMHF Flag-app — deterministic backend for BackendOracle smoke tests.

Endpoints:
    GET /sqli?id=        — leaks AMHF_FLAG_42 on tautology after double-decode.
    GET /xss?q=          — reflects q raw inside <div> for XSS oracle.
    GET /cmdi?cmd=       — argv subprocess.run, stdout includes amhf_cmd_marker.
    GET /lfi?file=       — allow-list read; canary path returns amhf_canary_v1.
    GET /sleep?ms=       — capped sleep up to 5000ms (time-blind oracle).
    GET /healthz         — liveness probe.

Hard rules (project security constraints):
    * subprocess.run(argv_list, shell=False) only.
    * No bare except.
    * No exposure outside the docker network — the WAFs are in front.

The literal markers AMHF_FLAG_, amhf_cmd_marker, amhf_canary_v1 are shared
contracts with amhf/oracle/_backend_helpers.py. Do not change strings.
"""

from __future__ import annotations

import os
import subprocess
import time
import urllib.parse
from pathlib import Path

from flask import Flask, Response, request

app = Flask(__name__)

# Allow-list root for /lfi. The Dockerfile populates /var/amhf with sample
# content and writes the literal canary at /etc/amhf_canary.
_LFI_ROOT = Path("/var/amhf").resolve()
_LFI_CANARY = Path("/etc/amhf_canary").resolve()


@app.get("/healthz")
def healthz() -> Response:
    return Response("ok\n", status=200, mimetype="text/plain")


@app.get("/sqli")
def sqli() -> Response:
    raw = request.args.get("id", "")
    # The WAF in front already did one HTTP-level decode. We do a SECOND
    # urllib.parse.unquote_plus to mimic the double-decode bug class that
    # makes ' OR '1'='1 leak after a double-encoded payload slips past the WAF.
    decoded = urllib.parse.unquote_plus(raw)
    if "' OR '1'='1" in decoded:
        body = (
            "<html><body>id=1 leaked secret token: AMHF_FLAG_42 ok</body></html>"
        )
        return Response(body, status=200, mimetype="text/html")
    return Response("ok", status=200, mimetype="text/plain")


@app.get("/xss")
def xss() -> Response:
    raw = request.args.get("q", "")
    decoded = urllib.parse.unquote_plus(raw)
    body = f"<html><body><div>You searched for: {decoded}</div></body></html>"
    return Response(body, status=200, mimetype="text/html")


@app.get("/cmdi")
def cmdi() -> Response:
    raw = request.args.get("cmd", "")
    decoded = urllib.parse.unquote_plus(raw)
    # NEVER shell=True — argv list with /bin/echo so the marker is always in stdout.
    completed = subprocess.run(  # noqa: S603 — argv list, no shell
        ["/bin/echo", "amhf_cmd_marker", decoded],
        shell=False,
        capture_output=True,
        timeout=2,
        check=False,
    )
    out = completed.stdout.decode("utf-8", errors="replace")
    # Cap output length defensively.
    return Response(out[:4096], status=200, mimetype="text/plain")


@app.get("/lfi")
def lfi() -> Response:
    raw = request.args.get("file", "")
    decoded = urllib.parse.unquote_plus(raw)
    try:
        target = Path(decoded).resolve()
    except (OSError, ValueError):
        return Response("forbidden\n", status=403, mimetype="text/plain")
    # Allow-list: anything under /var/amhf OR exactly /etc/amhf_canary.
    is_canary = target == _LFI_CANARY
    is_under_root = False
    try:
        target.relative_to(_LFI_ROOT)
        is_under_root = True
    except ValueError:
        is_under_root = False
    if not (is_canary or is_under_root):
        return Response("forbidden\n", status=403, mimetype="text/plain")
    if not target.is_file():
        return Response("not found\n", status=404, mimetype="text/plain")
    try:
        content = target.read_bytes()
    except OSError:
        return Response("io-error\n", status=500, mimetype="text/plain")
    return Response(content, status=200, mimetype="text/plain")


@app.get("/sleep")
def sleep_ep() -> Response:
    raw_ms = request.args.get("ms", "0")
    try:
        ms = max(0, min(int(raw_ms), 5000))
    except ValueError:
        ms = 0
    time.sleep(ms / 1000.0)
    return Response(f"slept {ms}ms\n", status=200, mimetype="text/plain")


if __name__ == "__main__":  # pragma: no cover — gunicorn is the prod path
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)  # noqa: S104 — bound only on amhf-net
