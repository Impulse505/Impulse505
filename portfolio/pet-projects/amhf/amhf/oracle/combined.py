"""CombinedOracle — оркестрирует WafOracle + BackendOracle + TimingOracle.

Это **единственная** точка входа, которую использует Stage-4 Orchestrator.
Логика принятия решения:

1. Транспортная ошибка → ``TRANSPORT_ERROR``.
2. WAF заблокировал → ``WAF_BLOCKED`` (даже если в ответе есть payload-echo).
3. 5xx без WAF-сигнатуры → ``SERVER_ERROR``.
4. Иначе — спрашиваем BackendOracle. Подтверждено → ``EXPLOIT_CONFIRMED``,
   bypass=True. Иначе — ``NO_EXPLOIT``.

Порядок (1)→(2)→(3)→(4) важен: XSS-payload, отражённый внутри WAF-page,
не должен подтверждаться как успешная эксплуатация — поэтому BackendOracle
вызывается только если WafOracle вернул False.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from amhf.config import OracleConfig
from amhf.delivery.request import FuzzResponse

from .backend_oracle import BackendOracle
from .timing_oracle import TimingOracle
from .waf_oracle import WafOracle


class OracleReason(StrEnum):
    """Причина итогового вердикта оракула — для лога и UI."""

    OK = "ok"
    WAF_BLOCKED = "waf_blocked"
    SERVER_ERROR = "server_error"
    NO_EXPLOIT = "no_exploit"
    EXPLOIT_CONFIRMED = "exploit_confirmed"
    TRANSPORT_ERROR = "transport_error"


@dataclass(frozen=True, slots=True)
class OracleVerdict:
    """Итоговый вердикт оракула для одной попытки фаззинга."""

    waf_blocked: bool
    waf_signature_hit: str | None
    exploit_confirmed: bool
    bypass: bool
    reason: OracleReason
    detail: str = ""
    server_error: bool = False


class CombinedOracle:
    """Single entry point for Stage-4 orchestrator.

    Аггрегирует решения WafOracle и BackendOracle; гарантирует, что
    ``bypass = (NOT waf_blocked) AND exploit_confirmed``.
    """

    def __init__(
        self,
        cfg: OracleConfig,
        timing: TimingOracle | None = None,
    ) -> None:
        self._waf = WafOracle(cfg.waf)
        self._backend = BackendOracle(cfg.backend, timing=timing)

    @property
    def waf(self) -> WafOracle:
        return self._waf

    @property
    def backend(self) -> BackendOracle:
        return self._backend

    def evaluate(
        self,
        resp: FuzzResponse,
        attack_class: str,
        *,
        payload_text: str | None = None,
        expected_markers: Sequence[str] = (),
    ) -> OracleVerdict:
        """Полная оценка одной попытки фаззинга."""
        # 1) Транспорт упал — нет смысла применять остальные оракулы.
        if resp.error is not None or resp.status_code == 0:
            return OracleVerdict(
                waf_blocked=False,
                waf_signature_hit=None,
                exploit_confirmed=False,
                bypass=False,
                reason=OracleReason.TRANSPORT_ERROR,
                detail=resp.error or "status_code=0",
            )

        # 2) WAF-блок имеет приоритет над любым backend-подтверждением.
        blocked, sig = self._waf.is_blocked(resp)
        if blocked:
            return OracleVerdict(
                waf_blocked=True,
                waf_signature_hit=sig,
                exploit_confirmed=False,
                bypass=False,
                reason=OracleReason.WAF_BLOCKED,
                detail=f"signature={sig!r}",
            )

        # 3) 5xx без WAF-сигнатуры — server-error, не bypass.
        if 500 <= resp.status_code < 600:
            return OracleVerdict(
                waf_blocked=False,
                waf_signature_hit=None,
                exploit_confirmed=False,
                bypass=False,
                reason=OracleReason.SERVER_ERROR,
                detail=f"http_{resp.status_code}",
                server_error=True,
            )

        # 4) Backend-проверка: подтверждение эксплуатации.
        confirmed, why = self._backend.confirm(
            resp,
            attack_class,
            payload_text=payload_text,
            expected_markers=expected_markers,
        )
        if confirmed:
            return OracleVerdict(
                waf_blocked=False,
                waf_signature_hit=None,
                exploit_confirmed=True,
                bypass=True,
                reason=OracleReason.EXPLOIT_CONFIRMED,
                detail=why,
            )
        return OracleVerdict(
            waf_blocked=False,
            waf_signature_hit=None,
            exploit_confirmed=False,
            bypass=False,
            reason=OracleReason.NO_EXPLOIT,
            detail="",
        )
