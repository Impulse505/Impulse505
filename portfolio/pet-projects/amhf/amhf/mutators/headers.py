"""Headers-layer мутаторы: 6 техник трансформации HTTP-заголовков.

Каждый мутатор работает только с ``req.headers``. Случайные мутаторы берут
энтропию исключительно из ``rng``.

Источники: RFC 7230 §3.2 (header fields), RFC 7239 (Forwarded),
PortSwigger HTTP Smuggling Lab, Akamai/Cloudflare bypass reports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from amhf.delivery.request import FuzzRequest
from amhf.mutators.base import Layer, MutatorId, RegistryOfMutators

if TYPE_CHECKING:
    import numpy as np


class _HeadersBase:
    """Общая часть headers-мутаторов: same-layer-правило + extras."""

    id: MutatorId
    layer: Layer = Layer.HEADERS
    extra_excludes: frozenset[str] = frozenset()

    def compatible_with(self, other: MutatorId) -> bool:
        if other in self.extra_excludes:
            return False
        try:
            other_mut = RegistryOfMutators.by_id(other)
        except KeyError:
            return True
        return other_mut.layer is not self.layer or other_mut.id == self.id


# --------------------------------------------------------------------------- #
# 1. duplicate — добавление дубля X-Original-URL                              #
# --------------------------------------------------------------------------- #
class Duplicate(_HeadersBase):
    """Добавляет дублирующий заголовок X-Original-URL = текущий URL.

    Пример: добавляет "X-Original-URL: /vuln?id=1"
    Источник: Bypass-report (Symfony, ASP.NET) — некоторые роутеры
    отдают приоритет X-Original-URL/X-Rewrite-URL перед request-line.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "duplicate"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_headers = dict(req.headers)
        # Извлекаем path+query из абсолютного URL.
        from urllib.parse import urlsplit

        sp = urlsplit(req.url)
        target = sp.path + (("?" + sp.query) if sp.query else "")
        new_headers["X-Original-URL"] = target
        return req.with_changes(headers=new_headers)


# --------------------------------------------------------------------------- #
# 2. case_jiggle — случайное переключение регистра имён заголовков           #
# --------------------------------------------------------------------------- #
class CaseJiggle(_HeadersBase):
    """Случайно перемешивает регистр символов в имени каждого заголовка.

    Пример (seed=0): "User-Agent" -> "uSeR-AgEnT"
    Источник: HTTP/1.1 заголовки case-insensitive — обход case-sensitive
    ACL некоторых WAF (см. Akamai bypass writeups).
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "case_jiggle"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        new_headers: dict[str, str] = {}
        for k, v in req.headers.items():
            flips = rng.integers(0, 2, size=len(k))
            jiggled = "".join(
                ch.upper() if int(flag) else ch.lower()
                for ch, flag in zip(k, flips, strict=True)
            )
            new_headers[jiggled] = v
        return req.with_changes(headers=new_headers)


# --------------------------------------------------------------------------- #
# 3. transfer_encoding_collision — TE: chunked + TE: identity                 #
# --------------------------------------------------------------------------- #
class TransferEncodingCollision(_HeadersBase):
    """Конфликтующие Transfer-Encoding для request-smuggling-фаззинга.

    Пример: добавляет "Transfer-Encoding: chunked, identity"
    Источник: PortSwigger HTTP/2 Smuggling, RFC 7230 §3.3.1.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "transfer_encoding_collision"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_headers = dict(req.headers)
        # Намеренно ставим conflicting list — некоторые back-ends берут
        # первый, некоторые последний (CVE-2019-18276 family).
        new_headers["Transfer-Encoding"] = "chunked, identity"
        return req.with_changes(headers=new_headers)


# --------------------------------------------------------------------------- #
# 4. xff_spoof — X-Forwarded-For со случайным IP                              #
# --------------------------------------------------------------------------- #
class XffSpoof(_HeadersBase):
    """Подделка X-Forwarded-For случайным внутренним IPv4 (RFC1918).

    Пример (seed=0): добавляет "X-Forwarded-For: 10.x.y.z"
    Источник: RFC 7239; обход IP-allow-list-WAF.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "xff_spoof"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        # Из RFC1918 случайно выбираем сеть и заполняем октеты.
        prefixes = ("10", "172", "192")
        prefix = prefixes[int(rng.integers(0, len(prefixes)))]
        if prefix == "10":
            ip = f"10.{int(rng.integers(0,256))}.{int(rng.integers(0,256))}.{int(rng.integers(1,255))}"
        elif prefix == "172":
            ip = f"172.{int(rng.integers(16,32))}.{int(rng.integers(0,256))}.{int(rng.integers(1,255))}"
        else:
            ip = f"192.168.{int(rng.integers(0,256))}.{int(rng.integers(1,255))}"
        new_headers = dict(req.headers)
        new_headers["X-Forwarded-For"] = ip
        return req.with_changes(headers=new_headers)


# --------------------------------------------------------------------------- #
# 5. accept_encoding_trick — Accept-Encoding: identity;q=0,*;q=1              #
# --------------------------------------------------------------------------- #
class AcceptEncodingTrick(_HeadersBase):
    """Подменяет Accept-Encoding на странное значение для confusion-атак.

    Пример: добавляет "Accept-Encoding: identity;q=0,*;q=1"
    Источник: RFC 7231 §5.3.4; обход некоторых reverse-proxy.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "accept_encoding_trick"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_headers = dict(req.headers)
        new_headers["Accept-Encoding"] = "identity;q=0,*;q=1"
        return req.with_changes(headers=new_headers)


# --------------------------------------------------------------------------- #
# 6. host_header_trick — двойной Host или Host injection                      #
# --------------------------------------------------------------------------- #
class HostHeaderTrick(_HeadersBase):
    """Добавляет X-Forwarded-Host со значением, отличным от Host.

    Пример: "Host: target" + "X-Forwarded-Host: evil.example"
    Источник: PortSwigger Host-header-attack lab; OWASP A05:2021.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "host_header_trick"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_headers = dict(req.headers)
        new_headers["X-Forwarded-Host"] = "evil.example"
        return req.with_changes(headers=new_headers)


# --------------------------------------------------------------------------- #
# Регистрация                                                                 #
# --------------------------------------------------------------------------- #
RegistryOfMutators.register(Duplicate())
RegistryOfMutators.register(CaseJiggle())
RegistryOfMutators.register(TransferEncodingCollision())
RegistryOfMutators.register(XffSpoof())
RegistryOfMutators.register(AcceptEncodingTrick())
RegistryOfMutators.register(HostHeaderTrick())


__all__ = [
    "AcceptEncodingTrick",
    "CaseJiggle",
    "Duplicate",
    "HostHeaderTrick",
    "TransferEncodingCollision",
    "XffSpoof",
]
