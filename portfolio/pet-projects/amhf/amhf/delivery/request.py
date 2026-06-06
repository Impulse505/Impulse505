"""FuzzRequest / FuzzResponse — иммутабельные модели одного шага фаззинга (FROZEN).

FuzzResponse обязательно несёт elapsed_ms — нужно для time-based-оракула,
который различает blind-SQLi по фактической задержке.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any


@dataclass(frozen=True, slots=True)
class FuzzRequest:
    """HTTP-запрос, проходящий через цепочку мутаторов."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    body_bytes: bytes = b""
    # Прикладные метаданные, читаются мутаторами и оракулом.
    attack_class: str = ""
    payload_id: str = ""
    payload_text: str = ""
    # Идентификатор поля, которое подлежит мутации payload-слоем.
    param_to_fuzz: str | None = None
    # Произвольные метки, которые мутаторы могут добавлять / читать.
    meta: dict[str, Any] = field(default_factory=dict)

    def with_changes(self, **changes: Any) -> FuzzRequest:
        """Return a copy with the given fields replaced (immutable update)."""
        return replace(self, **changes)


@dataclass(frozen=True, slots=True)
class FuzzResponse:
    """HTTP-ответ + метаданные, потребляемые оракулом."""

    status_code: int
    headers: dict[str, str]
    body_bytes: bytes
    body_text: str
    elapsed_ms: float
    # Если транспорт упал (timeout / DNS / reset), сюда попадает текст ошибки.
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True if no transport error and status_code < 500."""
        return self.error is None and self.status_code < 500
