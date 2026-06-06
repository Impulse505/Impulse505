"""Body-layer мутаторы: 7 техник трансформации тела HTTP-запроса.

Каждый мутатор работает с ``req.body_bytes`` и/или ``req.headers["Content-Type"]``.
Если входной контекст несовместим (например, json_form_swap при пустом body),
мутатор бросает MutationSkipped — оркестратор пропускает попытку.

Источники: RFC 7578 (multipart), RFC 7230 (chunked), RFC 8259 (JSON),
PortSwigger HPP Cheat Sheet, NAXSI/ModSec content-type evasion notes.
"""

from __future__ import annotations

import gzip
import json
import urllib.parse
from typing import TYPE_CHECKING

from amhf.delivery.request import FuzzRequest
from amhf.mutators.base import Layer, MutationSkipped, MutatorId, RegistryOfMutators

if TYPE_CHECKING:
    import numpy as np


_BOUNDARY_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)


class _BodyBase:
    """Общая часть body-мутаторов: same-layer-правило + явные исключения."""

    id: MutatorId
    layer: Layer = Layer.BODY
    extra_excludes: frozenset[str] = frozenset()

    def compatible_with(self, other: MutatorId) -> bool:
        if other in self.extra_excludes:
            return False
        try:
            other_mut = RegistryOfMutators.by_id(other)
        except KeyError:
            return True
        return other_mut.layer is not self.layer or other_mut.id == self.id


def _ensure_form_body(req: FuzzRequest) -> dict[str, str]:
    """Превратить ``req.body_bytes`` в dict ключ-значение (form-urlencoded)."""
    raw = req.body_bytes.decode("utf-8", errors="replace") if req.body_bytes else ""
    if not raw and req.param_to_fuzz:
        # Если тело пустое, синтезируем единственный параметр.
        return {req.param_to_fuzz: req.payload_text}
    parsed: dict[str, str] = {}
    for part in raw.split("&"):
        if not part:
            continue
        if "=" in part:
            k, _, v = part.partition("=")
            parsed[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
        else:
            parsed[urllib.parse.unquote(part)] = ""
    return parsed


# --------------------------------------------------------------------------- #
# 1. multipart_boundary — конвертирует body в multipart/form-data            #
# --------------------------------------------------------------------------- #
class MultipartBoundary(_BodyBase):
    """Преобразует form-данные в multipart/form-data со случайным boundary.

    Пример (seed=0): id=1 -> "--AAAAAAAA...\\r\\n..."
    Источник: RFC 7578 §4, обход WAF, не парсящих multipart глубоко.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "multipart_boundary"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        params = _ensure_form_body(req)
        if not params:
            raise MutationSkipped("multipart_boundary: empty body")
        # 24-символьный случайный boundary из ASCII-alnum.
        idxs = rng.integers(0, len(_BOUNDARY_ALPHABET), size=24)
        boundary = "".join(_BOUNDARY_ALPHABET[int(i)] for i in idxs)
        parts: list[bytes] = []
        for k, v in params.items():
            parts.append(f"--{boundary}\r\n".encode())
            parts.append(
                f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode()
            )
            parts.append(v.encode("utf-8") + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        body = b"".join(parts)
        new_headers = dict(req.headers)
        new_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        return req.with_changes(body_bytes=body, headers=new_headers)


# --------------------------------------------------------------------------- #
# 2. charset_juggle — трюк с charset в Content-Type                          #
# --------------------------------------------------------------------------- #
class CharsetJuggle(_BodyBase):
    """Подменяет charset в Content-Type на нестандартный (utf-16/ibm500).

    Пример: "application/x-www-form-urlencoded" ->
            "application/x-www-form-urlencoded; charset=ibm500"
    Источник: ModSec rule tuning notes, charset-evasion paper (2017).
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "charset_juggle"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_headers = dict(req.headers)
        ct = new_headers.get("Content-Type", "application/x-www-form-urlencoded")
        # Удаляем существующий charset=… и приклеиваем ibm500.
        base = ct.split(";")[0].strip()
        new_headers["Content-Type"] = f"{base}; charset=ibm500"
        return req.with_changes(headers=new_headers)


# --------------------------------------------------------------------------- #
# 3. param_pollution — HTTP Parameter Pollution в body                        #
# --------------------------------------------------------------------------- #
class ParamPollution(_BodyBase):
    """Дублирует фуззируемый параметр в body (HPP).

    Пример: "id=1" -> "id=1&id=' OR 1=1"
    Источник: PortSwigger HPP Cheat Sheet, OWASP Testing Guide §4.7.4.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "param_pollution"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        if not req.param_to_fuzz:
            raise MutationSkipped("param_pollution: param_to_fuzz is None")
        params = _ensure_form_body(req)
        # Кодируем оригинал и payload, склеиваем как ?k=a&k=b.
        original = params.get(req.param_to_fuzz, "")
        encoded_original = urllib.parse.quote(original, safe="")
        encoded_payload = urllib.parse.quote(req.payload_text, safe="")
        # Все остальные параметры — без дубликатов.
        other_pairs = [
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
            for k, v in params.items()
            if k != req.param_to_fuzz
        ]
        polluted = f"{req.param_to_fuzz}={encoded_original}&{req.param_to_fuzz}={encoded_payload}"
        body_str = "&".join([*other_pairs, polluted]) if other_pairs else polluted
        new_headers = dict(req.headers)
        new_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return req.with_changes(body_bytes=body_str.encode("utf-8"), headers=new_headers)


# --------------------------------------------------------------------------- #
# 4. json_form_swap — конвертация form -> json                                #
# --------------------------------------------------------------------------- #
class JsonFormSwap(_BodyBase):
    """Меняет form-urlencoded body на JSON со сменой Content-Type.

    Пример: "id=1" -> {"id": "1"}
    Источник: NAXSI evasion: WAF-правила для form могут не сработать на JSON.
    Совместимость: НЕ совместим с {multipart_boundary, param_pollution,
    content_type_swap} — все трое перетирают тот же контракт тела.
    """

    id: MutatorId = "json_form_swap"
    extra_excludes = frozenset(
        {"multipart_boundary", "param_pollution", "content_type_swap"}
    )

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        params = _ensure_form_body(req)
        if not params:
            raise MutationSkipped("json_form_swap: empty body")
        body = json.dumps(params, ensure_ascii=False).encode("utf-8")
        new_headers = dict(req.headers)
        new_headers["Content-Type"] = "application/json"
        return req.with_changes(body_bytes=body, headers=new_headers)


# --------------------------------------------------------------------------- #
# 5. content_type_swap — подмена Content-Type на text/plain                   #
# --------------------------------------------------------------------------- #
class ContentTypeSwap(_BodyBase):
    """Подменяет Content-Type на text/plain без переформатирования тела.

    Пример: "application/x-www-form-urlencoded" -> "text/plain"
    Источник: ModSec CRS notes — некоторые правила игнорируют не-form bodies.
    Совместимость: НЕ совместим с json_form_swap (оба пишут Content-Type).
    """

    id: MutatorId = "content_type_swap"
    extra_excludes = frozenset({"json_form_swap"})

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_headers = dict(req.headers)
        new_headers["Content-Type"] = "text/plain"
        return req.with_changes(headers=new_headers)


# --------------------------------------------------------------------------- #
# 6. gzip_encode — gzip-сжатие тела                                           #
# --------------------------------------------------------------------------- #
class GzipEncode(_BodyBase):
    """gzip-сжимает тело и выставляет Content-Encoding: gzip.

    Пример: "id=1" -> b'\\x1f\\x8b\\x08...'
    Источник: RFC 1952; обход content-only-WAF, не разжимающих body.
    Совместимость: НЕ совместим с chunked_encode (поведение не специфицировано).
    """

    id: MutatorId = "gzip_encode"
    extra_excludes = frozenset({"chunked_encode"})

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        # Параметр mtime=0 нужен для детерминированного выхода.
        compressed = gzip.compress(req.body_bytes, mtime=0)
        new_headers = dict(req.headers)
        new_headers["Content-Encoding"] = "gzip"
        new_headers["Content-Length"] = str(len(compressed))
        return req.with_changes(body_bytes=compressed, headers=new_headers)


# --------------------------------------------------------------------------- #
# 7. chunked_encode — Transfer-Encoding: chunked                              #
# --------------------------------------------------------------------------- #
class ChunkedEncode(_BodyBase):
    """Кодирует тело в chunked-поток с одним чанком.

    Пример: "id=1" -> "4\\r\\nid=1\\r\\n0\\r\\n\\r\\n"
    Источник: RFC 7230 §4.1; HTTP request-smuggling primer.
    Совместимость: НЕ совместим с gzip_encode.
    """

    id: MutatorId = "chunked_encode"
    extra_excludes = frozenset({"gzip_encode"})

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        body = req.body_bytes
        chunk_size_hex = f"{len(body):x}".encode("ascii")
        encoded = chunk_size_hex + b"\r\n" + body + b"\r\n0\r\n\r\n"
        new_headers = dict(req.headers)
        new_headers["Transfer-Encoding"] = "chunked"
        # Content-Length в chunked некорректен — удаляем, если был.
        new_headers.pop("Content-Length", None)
        return req.with_changes(body_bytes=encoded, headers=new_headers)


# --------------------------------------------------------------------------- #
# Регистрация                                                                 #
# --------------------------------------------------------------------------- #
RegistryOfMutators.register(MultipartBoundary())
RegistryOfMutators.register(CharsetJuggle())
RegistryOfMutators.register(ParamPollution())
RegistryOfMutators.register(JsonFormSwap())
RegistryOfMutators.register(ContentTypeSwap())
RegistryOfMutators.register(GzipEncode())
RegistryOfMutators.register(ChunkedEncode())


__all__ = [
    "CharsetJuggle",
    "ChunkedEncode",
    "ContentTypeSwap",
    "GzipEncode",
    "JsonFormSwap",
    "MultipartBoundary",
    "ParamPollution",
]
