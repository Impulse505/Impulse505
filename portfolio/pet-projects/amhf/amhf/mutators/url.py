"""URL-layer мутаторы: 6 техник трансформации request-line.

Каждый мутатор изменяет ``req.method`` и/или ``req.url`` (включая path,
query и fragment). Случайные мутаторы используют только ``rng``.

Источники: RFC 3986 (URI), RFC 7230 §5.3 (request-target), PortSwigger
URL-парсер-discrepancy lab, OWASP path-traversal cheat sheet.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

from amhf.delivery.request import FuzzRequest
from amhf.mutators.base import Layer, MutatorId, RegistryOfMutators

if TYPE_CHECKING:
    import numpy as np


class _UrlBase:
    """Общая часть url-мутаторов."""

    id: MutatorId
    layer: Layer = Layer.URL
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
# 1. method_case — нестандартный регистр HTTP-метода                         #
# --------------------------------------------------------------------------- #
class MethodCase(_UrlBase):
    """Меняет регистр HTTP-метода на смешанный (Get вместо GET).

    Пример: "GET" -> "Get"
    Источник: RFC 7230 § методы case-sensitive, но многие WAF
    нормализуют — рассинхронизация даёт обход.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "method_case"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_method = req.method.capitalize() if req.method else req.method
        return req.with_changes(method=new_method)


# --------------------------------------------------------------------------- #
# 2. path_normalize — внедрение ../ и //                                     #
# --------------------------------------------------------------------------- #
class PathNormalize(_UrlBase):
    """Вставляет конструкции "/.." и "//" в путь, провоцирующие нормализацию.

    Пример: "/vuln" -> "/a/../vuln"
    Источник: PortSwigger path-traversal lab; RFC 3986 §5.2.4.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "path_normalize"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        sp = urllib.parse.urlsplit(req.url)
        path = sp.path or "/"
        # /a/../<original_path_without_leading_slash>
        new_path = "/a/.." + path if path.startswith("/") else "a/../" + path
        new_url = urllib.parse.urlunsplit(
            (sp.scheme, sp.netloc, new_path, sp.query, sp.fragment)
        )
        return req.with_changes(url=new_url)


# --------------------------------------------------------------------------- #
# 3. percent_encode_path — percent-encoding всех символов пути              #
# --------------------------------------------------------------------------- #
class PercentEncodePath(_UrlBase):
    """Каждый символ пути заменяется на %NN (включая безопасные).

    Пример: "/vuln" -> "/%76%75%6c%6e"
    Источник: RFC 3986 §2.4; ModSec normalization rule notes.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "percent_encode_path"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        sp = urllib.parse.urlsplit(req.url)
        encoded = "/" + "/".join(
            "".join(f"%{b:02x}" for b in seg.encode("utf-8"))
            for seg in sp.path.lstrip("/").split("/")
        )
        # Если оригинал был без начального '/', сохраняем то же.
        if not sp.path.startswith("/"):
            encoded = encoded.lstrip("/")
        new_url = urllib.parse.urlunsplit(
            (sp.scheme, sp.netloc, encoded, sp.query, sp.fragment)
        )
        return req.with_changes(url=new_url)


# --------------------------------------------------------------------------- #
# 4. segment_inject — вставка ;param= в путь                                  #
# --------------------------------------------------------------------------- #
class SegmentInject(_UrlBase):
    """Внедряет matrix-параметр (";x=y") в один из сегментов пути.

    Пример (seed=0): "/vuln" -> "/vuln;jsessionid=AAAA"
    Источник: RFC 3986 §3.3 (path segments); J2EE jsessionid trick.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "segment_inject"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        sp = urllib.parse.urlsplit(req.url)
        path = sp.path
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        idxs = rng.integers(0, len(alphabet), size=8)
        token = "".join(alphabet[int(i)] for i in idxs)
        # Лепим matrix-параметр к последнему непустому сегменту.
        segments = path.split("/")
        for i in range(len(segments) - 1, -1, -1):
            if segments[i]:
                segments[i] = segments[i] + f";jsessionid={token}"
                break
        else:
            # Совсем пустой path — добавляем сегмент с jsessionid.
            segments = ["", f";jsessionid={token}"]
        new_path = "/".join(segments)
        new_url = urllib.parse.urlunsplit(
            (sp.scheme, sp.netloc, new_path, sp.query, sp.fragment)
        )
        return req.with_changes(url=new_url)


# --------------------------------------------------------------------------- #
# 5. fragment_inject — добавление фрагмента                                   #
# --------------------------------------------------------------------------- #
class FragmentInject(_UrlBase):
    """Добавляет «обманный» фрагмент к URL.

    Пример: "/vuln?id=1" -> "/vuln?id=1#"
    Источник: RFC 3986 §3.5; обход URL-парсеров, не отрезающих fragment
    при отправке (нарушение клиента).
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "fragment_inject"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        sp = urllib.parse.urlsplit(req.url)
        new_url = urllib.parse.urlunsplit(
            (sp.scheme, sp.netloc, sp.path, sp.query, "amhf")
        )
        return req.with_changes(url=new_url)


# --------------------------------------------------------------------------- #
# 6. query_encoding — percent-encoding ключей и значений query                #
# --------------------------------------------------------------------------- #
class QueryEncoding(_UrlBase):
    """Полностью percent-encode'ит каждое имя/значение query-параметра.

    Пример: "?id=1" -> "?%69%64=%31"
    Источник: RFC 3986 §3.4; обход WAF-правил по структуре query.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "query_encoding"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        sp = urllib.parse.urlsplit(req.url)
        # Берём query из URL, парсим и кодируем каждый октет.
        pairs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
        encoded_pairs = []
        for k, v in pairs:
            ek = "".join(f"%{b:02x}" for b in k.encode("utf-8"))
            ev = "".join(f"%{b:02x}" for b in v.encode("utf-8"))
            encoded_pairs.append(f"{ek}={ev}")
        new_query = "&".join(encoded_pairs)
        new_url = urllib.parse.urlunsplit(
            (sp.scheme, sp.netloc, sp.path, new_query, sp.fragment)
        )
        return req.with_changes(url=new_url)


# --------------------------------------------------------------------------- #
# Регистрация                                                                 #
# --------------------------------------------------------------------------- #
RegistryOfMutators.register(MethodCase())
RegistryOfMutators.register(PathNormalize())
RegistryOfMutators.register(PercentEncodePath())
RegistryOfMutators.register(SegmentInject())
RegistryOfMutators.register(FragmentInject())
RegistryOfMutators.register(QueryEncoding())


__all__ = [
    "FragmentInject",
    "MethodCase",
    "PathNormalize",
    "PercentEncodePath",
    "QueryEncoding",
    "SegmentInject",
]
