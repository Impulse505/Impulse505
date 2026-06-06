"""Helpers for BackendOracle — сюда вынесена реализация class-checks,
чтобы модуль ``backend_oracle.py`` оставался компактным."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from amhf.config import BackendOracleConfig
from amhf.delivery.request import FuzzResponse

from .reflection_check import is_xss_reflected
from .timing_oracle import TimingOracle

# Эвристические маркеры команды (CMDi).
_CMDI_HEURISTICS: tuple[str, ...] = ("uid=", "gid=", "root:x:")

# /etc/passwd-style маркер для path-traversal.
_PASSWD_MARKER = "root:x:0:0"

# Pseudo-marker, сигнализирующий о time-based blind.
_TIME_DELAY_PSEUDO = "__TIME_DELAY__"


@dataclass(frozen=True, slots=True)
class _Compiled:
    """Скомпилированные паттерны для SQLi-error matching."""

    sqli_error_patterns: tuple[re.Pattern[str], ...]


def compile_patterns(cfg: BackendOracleConfig) -> _Compiled:
    """Pre-compile SQLi error signatures (case-insensitive substring/regex)."""
    # Сигнатуры из конфига интерпретируем как substring; экранируем на всякий случай.
    patterns = tuple(
        re.compile(re.escape(sig), re.IGNORECASE)
        for sig in cfg.sqli.error_signatures
    )
    return _Compiled(sqli_error_patterns=patterns)


def check_sqli(
    resp: FuzzResponse,
    cfg: BackendOracleConfig,
    compiled: _Compiled,
    expected_markers: Sequence[str],
    timing: TimingOracle | None,
) -> tuple[bool, str]:
    """SQLi: error-pattern → flag-marker → time-delay (по pseudo-marker)."""
    body = resp.body_text
    # 1) Серверные DB-ошибки.
    for pat in compiled.sqli_error_patterns:
        if pat.search(body):
            return (True, f"sql-error: matched {pat.pattern!r}")
    # 2) Flag-app marker — литерал.
    flag = cfg.sqli.flag_marker
    if flag and flag in body:
        # Захватываем сам токен "AMHF_FLAG_<id>" для отчёта.
        idx = body.find(flag)
        token = body[idx : idx + len(flag) + 16].split()[0].rstrip(".,;:'\"")
        return (True, f"flag-marker: {token}")
    # 3) Time-based blind — только если payload помечен в corpus.
    if (
        _TIME_DELAY_PSEUDO in expected_markers
        and timing is not None
        and timing.is_delayed(resp.elapsed_ms)
    ):
        return (
            True,
            f"timing-blind: {resp.elapsed_ms:.0f}ms > {timing.threshold_ms:.0f}ms",
        )
    return (False, "")


def check_xss(
    resp: FuzzResponse,
    payload_text: str | None,
    expected_markers: Sequence[str],
) -> tuple[bool, str]:
    """XSS: reflection в исполнимом HTML-контексте (payload не html-escape-нут)."""
    body = resp.body_text
    # Берём payload из аргумента; если нет — пытаемся вычленить из expected_markers
    # как fallback (часть corpus-entries содержит payload в expected_markers).
    payload: str | None = payload_text
    if not payload:
        for marker in expected_markers:
            if marker.startswith("<") or "=" in marker:
                payload = marker
                break
    if not payload:
        return (False, "")
    reflected, reason = is_xss_reflected(payload, body)
    if reflected:
        return (True, reason)
    return (False, "")


def check_cmdi(resp: FuzzResponse, cfg: BackendOracleConfig) -> tuple[bool, str]:
    """CMDi: literal command_marker → эвристики (uid=, gid=, root:x:)."""
    body = resp.body_text
    marker = cfg.cmdi.command_marker
    if marker and marker in body:
        return (True, "cmd-marker")
    for heuristic in _CMDI_HEURISTICS:
        if heuristic in body:
            return (True, f"cmd-heuristic: {heuristic!r}")
    return (False, "")


def check_pathtrav(resp: FuzzResponse, cfg: BackendOracleConfig) -> tuple[bool, str]:
    """PathTrav: literal canary_marker → /etc/passwd шаблон."""
    body = resp.body_text
    canary = cfg.pathtrav.canary_marker
    if canary and canary in body:
        return (True, "canary-marker")
    if _PASSWD_MARKER in body:
        return (True, f"passwd-marker: {_PASSWD_MARKER!r}")
    return (False, "")
