"""AttemptRecord — pydantic v2 запись одной попытки фаззинга (FROZEN).

Схема стабильна на всю жизнь проекта: 18 полей. Изменение требует RFC.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AttemptKind(StrEnum):
    """Источник хромосомы: базовая сетка, мутация UCB1, потомок GA."""

    BASELINE = "baseline"
    MUTATION = "mutation"
    GA_OFFSPRING = "ga_offspring"


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class AttemptRecord(BaseModel):
    """Одна строка лога эксперимента."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # --- идентификаторы ---
    timestamp: datetime = Field(default_factory=_utcnow)
    run_id: str
    attempt_no: int = Field(ge=0)
    target_id: str
    payload_id: str
    payload_text: str

    # --- мутация ---
    chromosome: list[str] = Field(default_factory=list)
    mutated_request_summary: str = ""

    # --- транспорт ---
    status_code: int = Field(ge=0, le=999)
    response_time_ms: float = Field(ge=0.0)

    # --- оракул ---
    waf_blocked: bool
    waf_signature_hit: str | None = None
    exploit_confirmed: bool
    oracle_reason: str = ""
    bypass: bool

    # --- bandit / etc. ---
    ucb_reward: int = Field(ge=0, le=1)
    attempt_kind: AttemptKind = AttemptKind.MUTATION
    seed: int
