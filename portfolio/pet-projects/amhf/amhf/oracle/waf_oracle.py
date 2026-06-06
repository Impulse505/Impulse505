"""WafOracle — детектор блокировки запроса WAF-ом.

Возвращает кортеж ``(blocked, signature_hit)``: первый элемент — флаг
блокировки, второй — название сработавшей сигнатуры (либо ``None``).

Правила (Stage 3):
  1. ``status_code in cfg.blocked_codes`` — блок, сигнатура ``"http_<code>"``.
  2. Любая ``signature`` из ``cfg.blocked_body_signatures`` — substring
     ``resp.body_text`` (case-sensitive).
  3. Soft-hint: ``status_code == 200`` И сигнатура найдена И размер тела
     ``<= cfg.block_page_size_max`` — это "ModSecurity 200 block page".
  4. 5xx — не блок WAF (классифицируется CombinedOracle как ``server_error``).
  5. Транспортная ошибка (``error is not None`` или ``status_code == 0``) —
     не блок (классифицируется как ``transport_error``).
"""

from __future__ import annotations

from amhf.config import WafOracleConfig
from amhf.delivery.request import FuzzResponse


class WafOracle:
    """Детектор блокировки WAF на основе кода ответа и сигнатур тела."""

    def __init__(self, cfg: WafOracleConfig) -> None:
        # Замораживаем коллекции в локальных полях для быстрого матчинга.
        self._blocked_codes: frozenset[int] = frozenset(cfg.blocked_codes)
        self._signatures: tuple[str, ...] = tuple(cfg.blocked_body_signatures)
        self._block_page_size_max: int = cfg.block_page_size_max

    def is_blocked(self, resp: FuzzResponse) -> tuple[bool, str | None]:
        """Возвращает (blocked, signature_hit)."""
        # Транспортная ошибка — это не WAF-блок.
        if resp.error is not None or resp.status_code == 0:
            return (False, None)

        # 1) Жёстко-блокирующие HTTP-коды.
        if resp.status_code in self._blocked_codes:
            return (True, f"http_{resp.status_code}")

        # 2) Сигнатура в теле — но только если status_code != 5xx
        # (5xx CombinedOracle классифицирует отдельно как server_error).
        if 500 <= resp.status_code < 600:
            return (False, None)

        # Поиск сигнатуры case-sensitive substring.
        body = resp.body_text
        for sig in self._signatures:
            if sig not in body:
                continue
            # 3) Если код 200 — применяем soft body-size hint.
            if resp.status_code == 200 and len(resp.body_bytes) > self._block_page_size_max:
                # Большое 200-тело с сигнатурой — скорее echo, не block-page.
                continue
            return (True, sig)

        return (False, None)
