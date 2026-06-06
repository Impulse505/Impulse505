"""Payload-layer мутаторы: 12 техник трансформации строки полезной нагрузки.

Каждый мутатор берёт ``req.payload_text``, преобразует строку и подставляет
результат в ``req.query[req.param_to_fuzz]``, если параметр задан и
присутствует в query. Тип — pure-функция в обёртке-классе; никакой
внутренней мутабельной памяти. Случайные мутаторы используют только
``rng`` (numpy.random.Generator), что обеспечивает воспроизводимость.

Источники: PortSwigger SQLi/XSS Cheat Sheets, OWASP Testing Guide,
RFC 3986 (percent-encoding), RFC 1866 (HTML entities).
"""

from __future__ import annotations

import base64 as _b64
import urllib.parse
from typing import TYPE_CHECKING

from amhf.delivery.request import FuzzRequest
from amhf.mutators.base import Layer, MutatorId, RegistryOfMutators

if TYPE_CHECKING:
    import numpy as np


# --------------------------------------------------------------------------- #
# Базовый класс с правилом "только same-layer запрещён"                       #
# --------------------------------------------------------------------------- #
class _PayloadBase:
    """Общая часть payload-мутаторов: типизация + same-layer-правило."""

    id: MutatorId
    layer: Layer = Layer.PAYLOAD
    # Доп.список явно несовместимых id (помимо same-layer-правила).
    extra_excludes: frozenset[str] = frozenset()

    def compatible_with(self, other: MutatorId) -> bool:
        if other in self.extra_excludes:
            return False
        try:
            other_mut = RegistryOfMutators.by_id(other)
        except KeyError:
            # Регистрация может ещё не произойти — считаем совместимым.
            return True
        # Любой другой мутатор того же слоя — несовместим (orchestrator
        # выбирает не более одного на слой).
        return other_mut.layer is not self.layer or other_mut.id == self.id

    @staticmethod
    def _apply_to_request(req: FuzzRequest, new_payload: str) -> FuzzRequest:
        """Подставить трансформированный payload в query, если возможно."""
        new_query = dict(req.query)
        if req.param_to_fuzz and req.param_to_fuzz in new_query:
            new_query[req.param_to_fuzz] = new_payload
        return req.with_changes(payload_text=new_payload, query=new_query)


# --------------------------------------------------------------------------- #
# 1. url_encode — percent-encoding всех «небезопасных» символов              #
# --------------------------------------------------------------------------- #
class UrlEncode(_PayloadBase):
    """Percent-encoding всех символов, кроме ASCII-букв и цифр.

    Пример: "' OR 1=1" -> "%27%20OR%201%3D1"
    Источник: RFC 3986 §2.1, PortSwigger SQLi Cheat Sheet.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "url_encode"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng  # детерминированный мутатор
        new_payload = urllib.parse.quote(req.payload_text, safe="")
        return self._apply_to_request(req, new_payload)


# --------------------------------------------------------------------------- #
# 2. double_url_encode — двойное percent-encoding                            #
# --------------------------------------------------------------------------- #
class DoubleUrlEncode(_PayloadBase):
    """Двойное percent-encoding — обходит одношаговые URL-нормализаторы WAF.

    Пример: "' OR 1=1" -> "%2527%2520OR%25201%253D1"
    Источник: PortSwigger SQLi Cheat Sheet, OWASP Testing Guide §4.7.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "double_url_encode"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        once = urllib.parse.quote(req.payload_text, safe="")
        twice = urllib.parse.quote(once, safe="")
        return self._apply_to_request(req, twice)


# --------------------------------------------------------------------------- #
# 3. html_entity — &#NN;-кодирование каждого символа                         #
# --------------------------------------------------------------------------- #
class HtmlEntity(_PayloadBase):
    """Кодирование каждого символа в десятичную HTML-сущность &#NN;.

    Пример: "<a>" -> "&#60;&#97;&#62;"
    Источник: RFC 1866 §3.2.3, OWASP XSS Cheat Sheet.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "html_entity"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_payload = "".join(f"&#{ord(c)};" for c in req.payload_text)
        return self._apply_to_request(req, new_payload)


# --------------------------------------------------------------------------- #
# 4. unicode_escape — \uNNNN для каждого символа                              #
# --------------------------------------------------------------------------- #
class UnicodeEscape(_PayloadBase):
    """Кодирование каждого символа в JS-стиле \\uNNNN.

    Пример: "<a>" -> "\\u003c\\u0061\\u003e"
    Источник: ECMAScript §11.8.4, PortSwigger XSS Cheat Sheet.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "unicode_escape"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_payload = "".join(f"\\u{ord(c):04x}" for c in req.payload_text)
        return self._apply_to_request(req, new_payload)


# --------------------------------------------------------------------------- #
# 5. hex_encode — \xNN для каждого байта UTF-8                               #
# --------------------------------------------------------------------------- #
class HexEncode(_PayloadBase):
    """Hex-кодирование каждого байта UTF-8 в форму \\xNN.

    Пример: "AB" -> "\\x41\\x42"
    Источник: MySQL/MSSQL hex-литералы, OWASP SQLi Bypass Cheat Sheet.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "hex_encode"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        raw = req.payload_text.encode("utf-8")
        new_payload = "".join(f"\\x{b:02x}" for b in raw)
        return self._apply_to_request(req, new_payload)


# --------------------------------------------------------------------------- #
# 6. base64 — base64-кодирование UTF-8                                       #
# --------------------------------------------------------------------------- #
class Base64Encode(_PayloadBase):
    """Base64-кодирование payload как UTF-8-байтов.

    Пример: "AB" -> "QUI="
    Источник: RFC 4648, NAXSI/ModSec base64-evasion patterns.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "base64"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        raw = req.payload_text.encode("utf-8")
        new_payload = _b64.b64encode(raw).decode("ascii")
        return self._apply_to_request(req, new_payload)


# --------------------------------------------------------------------------- #
# 7. comment_inject — вставка SQL-комментариев между символами               #
# --------------------------------------------------------------------------- #
class CommentInject(_PayloadBase):
    """Вставляет SQL-комментарий /\\*\\*/ между парами символов.

    Пример (seed=0): "OR" -> "O/\\*\\*/R"
    Источник: PortSwigger SQLi Cheat Sheet, ModSec CRS rules 942.x.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "comment_inject"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        styles = ("/**/", "/*x*/", "--+\n")
        text = req.payload_text
        if not text:
            return self._apply_to_request(req, text)
        # Случайный стиль и случайная позиция вставки.
        style = styles[int(rng.integers(0, len(styles)))]
        # Гарантируем хотя бы одну вставку, если payload длиннее 1.
        if len(text) <= 1:
            return self._apply_to_request(req, text + style)
        pos = int(rng.integers(1, len(text)))
        new_payload = text[:pos] + style + text[pos:]
        return self._apply_to_request(req, new_payload)


# --------------------------------------------------------------------------- #
# 8. case_toggle — инверсия регистра букв                                     #
# --------------------------------------------------------------------------- #
class CaseToggle(_PayloadBase):
    """Полная инверсия регистра всех букв payload.

    Пример: "Or 1=1" -> "oR 1=1"
    Источник: ModSec CRS, обход case-sensitive blacklist.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "case_toggle"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_payload = req.payload_text.swapcase()
        return self._apply_to_request(req, new_payload)


# --------------------------------------------------------------------------- #
# 9. whitespace_tricks — замена пробелов на разные whitespace-символы        #
# --------------------------------------------------------------------------- #
class WhitespaceTricks(_PayloadBase):
    """Замена пробела на TAB/VT/FF/NL — обход примитивных регексов.

    Пример (seed=0): "OR 1=1" -> "OR\\t1=1"
    Источник: OWASP SQL Injection Bypass Cheat Sheet.
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "whitespace_tricks"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        alts = ("\t", "\v", "\f", "\n", "\r")
        text = req.payload_text
        # Каждый пробел замещаем независимо выбранным альтернативным символом.
        chars = []
        for ch in text:
            if ch == " ":
                chars.append(alts[int(rng.integers(0, len(alts)))])
            else:
                chars.append(ch)
        return self._apply_to_request(req, "".join(chars))


# --------------------------------------------------------------------------- #
# 10. null_byte — добавление %00 в конец                                      #
# --------------------------------------------------------------------------- #
class NullByte(_PayloadBase):
    """Добавление null-byte (%00) в конец payload — truncation-trick.

    Пример: "x.txt" -> "x.txt%00"
    Источник: OWASP Testing Guide §4.7.6 (poison null byte).
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "null_byte"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        new_payload = req.payload_text + "%00"
        return self._apply_to_request(req, new_payload)


# --------------------------------------------------------------------------- #
# 11. keyword_fragment — разрыв ключевых слов SQL                             #
# --------------------------------------------------------------------------- #
class KeywordFragment(_PayloadBase):
    """Фрагментация ключевых слов SQL пустым комментарием.

    Пример: "UNION SELECT" -> "UN/**/ION SEL/**/ECT"
    Источник: PortSwigger SQLi, обход keyword-blacklist (libinjection).
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "keyword_fragment"
    _KEYWORDS = (
        "UNION", "SELECT", "INSERT", "UPDATE", "DELETE",
        "FROM", "WHERE", "AND", "OR", "NULL", "FROM",
    )

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        text = req.payload_text
        upper = text.upper()
        out: list[str] = []
        i = 0
        while i < len(text):
            matched = False
            for kw in self._KEYWORDS:
                if upper.startswith(kw, i) and len(kw) >= 2:
                    # Вставляем /**/ после второго символа ключевого слова.
                    out.append(text[i : i + 2] + "/**/" + text[i + 2 : i + len(kw)])
                    i += len(kw)
                    matched = True
                    break
            if not matched:
                out.append(text[i])
                i += 1
        return self._apply_to_request(req, "".join(out))


# --------------------------------------------------------------------------- #
# 12. charset_trick — переключение charset через ;charset=                    #
# --------------------------------------------------------------------------- #
class CharsetTrick(_PayloadBase):
    """Добавление UTF-7-стиля заголовка перед payload — обход charset-парсеров.

    Пример: "<script>" -> "+ADw-script+AD4-"
    Источник: OWASP XSS Cheat Sheet (UTF-7 XSS).
    Совместимость: только same-layer (по контракту слоя).
    """

    id: MutatorId = "charset_trick"

    def mutate(self, req: FuzzRequest, rng: np.random.Generator) -> FuzzRequest:
        del rng
        try:
            encoded = req.payload_text.encode("utf-7").decode("ascii")
        except UnicodeError:
            encoded = req.payload_text
        return self._apply_to_request(req, encoded)


# --------------------------------------------------------------------------- #
# Регистрация в глобальном реестре (выполняется при импорте модуля).         #
# --------------------------------------------------------------------------- #
RegistryOfMutators.register(UrlEncode())
RegistryOfMutators.register(DoubleUrlEncode())
RegistryOfMutators.register(HtmlEntity())
RegistryOfMutators.register(UnicodeEscape())
RegistryOfMutators.register(HexEncode())
RegistryOfMutators.register(Base64Encode())
RegistryOfMutators.register(CommentInject())
RegistryOfMutators.register(CaseToggle())
RegistryOfMutators.register(WhitespaceTricks())
RegistryOfMutators.register(NullByte())
RegistryOfMutators.register(KeywordFragment())
RegistryOfMutators.register(CharsetTrick())


__all__ = [
    "Base64Encode",
    "CaseToggle",
    "CharsetTrick",
    "CommentInject",
    "DoubleUrlEncode",
    "HexEncode",
    "HtmlEntity",
    "KeywordFragment",
    "NullByte",
    "UnicodeEscape",
    "UrlEncode",
    "WhitespaceTricks",
]
