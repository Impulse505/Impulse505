"""Интерфейс мутатора и реестр.

Канонический порядок применения слоёв: PAYLOAD -> BODY -> HEADERS -> URL.
MutatorId — единый «строковый алфавит» хромосом, конфигов и тестов;
задаётся как typing.Literal и фиксируется на весь проект (FROZEN).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    import numpy as np

    from amhf.delivery.request import FuzzRequest


# Алфавит из 31 идентификатора мутаторов; правится только через RFC.
MutatorId = Literal[
    # payload-layer (12)
    "url_encode", "double_url_encode", "html_entity", "unicode_escape",
    "hex_encode", "base64", "comment_inject", "case_toggle",
    "whitespace_tricks", "null_byte", "keyword_fragment", "charset_trick",
    # body-layer (7)
    "multipart_boundary", "charset_juggle", "param_pollution",
    "json_form_swap", "content_type_swap", "gzip_encode", "chunked_encode",
    # headers-layer (6)
    "duplicate", "case_jiggle", "transfer_encoding_collision",
    "xff_spoof", "accept_encoding_trick", "host_header_trick",
    # url-layer (6)
    "method_case", "path_normalize", "percent_encode_path",
    "segment_inject", "fragment_inject", "query_encoding",
]


class Layer(StrEnum):
    """Слой мутации; порядок объявления = канонический порядок применения."""

    PAYLOAD = "payload"
    BODY = "body"
    HEADERS = "headers"
    URL = "url"


class MutationSkipped(Exception):
    """Контекст несовместим — оркестратор пропускает попытку и логирует skip."""


@dataclass(slots=True)
class MutationContext:
    """Контекст одного шага мутации (класс атаки, payload, текущая хромосома)."""

    attack_class: str
    payload_id: str
    chromosome: tuple[str, ...]
    extras: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class Mutator(Protocol):
    """Протокол мутатора. Детерминирован при фиксированном rng (FROZEN)."""

    id: MutatorId
    layer: Layer

    def compatible_with(self, other: MutatorId) -> bool: ...

    def mutate(
        self, req: FuzzRequest, rng: np.random.Generator
    ) -> FuzzRequest: ...


class Registry:
    """Реестр мутаторов: индексы по id и по слою."""

    def __init__(self) -> None:
        self._by_id: dict[str, Mutator] = {}
        self._by_layer: dict[Layer, list[Mutator]] = {ly: [] for ly in Layer}

    def register(self, mutator: Mutator) -> Mutator:
        if mutator.id in self._by_id:
            raise ValueError(f"Mutator id уже зарегистрирован: {mutator.id}")
        self._by_id[mutator.id] = mutator
        self._by_layer[mutator.layer].append(mutator)
        return mutator

    def by_id(self, mid: str) -> Mutator:
        return self._by_id[mid]

    def by_layer(self, layer: Layer) -> list[Mutator]:
        return list(self._by_layer[layer])

    def all_ids(self) -> Iterable[str]:
        return self._by_id.keys()


# Глобальный реестр; конкретные мутаторы регистрируются при импорте.
RegistryOfMutators: Registry = Registry()
