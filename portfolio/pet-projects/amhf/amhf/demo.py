"""Embedded mock target used by ``amhf demo`` (and replicated in tests).

Содержит минимальный набор aiohttp-обработчиков, который имитирует
WAF + уязвимый backend в одном процессе. SQLi-обработчик использует
строгую logic, синхронизированную с ``tests/integration/test_e2e_adaptive``:
только ``double_url_encode`` обходит WAF, поэтому ``amhf demo`` сразу
показывает измеримую асимметрию adaptive vs random (ratio ≥ 1.5×).

XSS / CMDi / LFI / sleep — более мягкие; используются e2e_local тестом
для покрытия всех 4 классов атак.
"""

from __future__ import annotations

import asyncio
import urllib.parse

from aiohttp import web

_BLOCK_BODY_SQLI = "<html>ModSecurity blocked your request</html>"
_BLOCK_BODY_CMDI = "<html>ModSecurity Access Denied (CMDi pattern)</html>"
_BLOCK_BODY_LFI = "<html>ModSecurity Access Denied (LFI pattern)</html>"


def _waf_view(value_decoded_once: str) -> str:
    """Что видит WAF после стандартного одного декодирования HTTP-сервером."""
    return value_decoded_once


def _backend_view(value_decoded_once: str) -> str:
    """Что видит backend после второго urldecode."""
    return urllib.parse.unquote_plus(value_decoded_once)


def _strict_waf_blocks_sqli(waf_view: str) -> bool:
    """Strict WAF: блокирует всё, кроме double-encoded SQLi.

    Совпадает с ``_strict_waf_blocks`` из tests/integration/test_e2e_adaptive.
    Блокируется при наличии: литеральной тавтологии, любой одинокой кавычки,
    ключевого слова ``OR`` рядом с пробелом/плюсом, либо пары UNION+SELECT.
    """
    upper = waf_view.upper()
    if "' OR '1'='1" in waf_view:
        return True
    if "'" in waf_view:
        return True
    if " OR " in upper or "+OR+" in upper:
        return True
    return "UNION" in upper and "SELECT" in upper


async def _sqli_handler(request: web.Request) -> web.Response:
    once = request.rel_url.query.get("id", "")
    if _strict_waf_blocks_sqli(_waf_view(once)):
        return web.Response(text=_BLOCK_BODY_SQLI, status=403)
    # Backend выполняет ВТОРОЙ urldecode — это и есть симулируемый баг
    # double-decode-приложения. Утечка флага только при восстановленной тавтологии.
    decoded = _backend_view(once)
    if "' OR '1'='1" in decoded:
        body = (
            "<html><body>id=1 leaked secret token: AMHF_FLAG_42 ok</body></html>"
        )
        return web.Response(text=body, status=200)
    return web.Response(text="ok", status=200)


async def _xss_handler(request: web.Request) -> web.Response:
    once = request.rel_url.query.get("q", "")
    waf_view = _waf_view(once)
    if "<script>" in waf_view.lower():
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


__all__ = ["make_mock_app"]
