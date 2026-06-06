"""Unit tests for amhf.mutators.payload — 12 mutators."""

from __future__ import annotations

import base64 as _b64
import html
import urllib.parse

import numpy as np
import pytest

# Импорт пакета — гарантия регистрации всех 31 мутатора в реестре.
import amhf.mutators  # noqa: F401
from amhf.delivery.request import FuzzRequest
from amhf.mutators import payload as P  # noqa: N812 (single-letter alias for tests)
from amhf.mutators.base import Layer, RegistryOfMutators

# --- Хелперы --------------------------------------------------------------- #


def _make_req(text: str = "' OR 1=1") -> FuzzRequest:
    return FuzzRequest(
        method="GET",
        url="http://localhost/vuln?id=1",
        headers={"User-Agent": "amhf/test"},
        query={"id": "1"},
        body_bytes=b"",
        attack_class="sqli",
        payload_id="t1",
        payload_text=text,
        param_to_fuzz="id",
    )


def _rng(seed: int = 0) -> np.random.Generator:
    return np.random.default_rng(seed)


# --- 1. UrlEncode ---------------------------------------------------------- #


def test_url_encode_golden() -> None:
    req = _make_req("' OR 1=1")
    out = P.UrlEncode().mutate(req, _rng())
    assert out.payload_text == "%27%20OR%201%3D1"
    assert out.query["id"] == "%27%20OR%201%3D1"


def test_url_encode_unicode_edge() -> None:
    # Кириллица — кодируется в utf-8, потом percent-encode.
    req = _make_req("Привет")
    out = P.UrlEncode().mutate(req, _rng())
    assert urllib.parse.unquote(out.payload_text) == "Привет"


def test_url_encode_property() -> None:
    for seed in range(50):
        rng = _rng(seed)
        s = "".join(chr(int(rng.integers(32, 127))) for _ in range(20))
        req = _make_req(s)
        out = P.UrlEncode().mutate(req, rng)
        assert urllib.parse.unquote(out.payload_text) == s


# --- 2. DoubleUrlEncode ---------------------------------------------------- #


def test_double_url_encode_golden() -> None:
    req = _make_req("' OR")
    out = P.DoubleUrlEncode().mutate(req, _rng())
    assert out.payload_text == "%2527%2520OR"


def test_double_url_encode_property() -> None:
    for seed in range(50):
        rng = _rng(seed)
        s = "".join(chr(int(rng.integers(32, 127))) for _ in range(15))
        req = _make_req(s)
        out = P.DoubleUrlEncode().mutate(req, rng)
        # Двойной decode даёт исходный.
        assert urllib.parse.unquote(urllib.parse.unquote(out.payload_text)) == s


# --- 3. HtmlEntity --------------------------------------------------------- #


def test_html_entity_golden() -> None:
    req = _make_req("<a>")
    out = P.HtmlEntity().mutate(req, _rng())
    assert out.payload_text == "&#60;&#97;&#62;"


def test_html_entity_long_input() -> None:
    long_text = "x" * 8192
    out = P.HtmlEntity().mutate(_make_req(long_text), _rng())
    assert html.unescape(out.payload_text) == long_text


def test_html_entity_property() -> None:
    for seed in range(50):
        rng = _rng(seed)
        # Skip C1 control range (0x80..0x9F): WHATWG html.unescape rewrites
        # them to spec-mandated replacement codepoints, breaking round-trip.
        s = "".join(chr(int(rng.integers(32, 127))) for _ in range(10))
        out = P.HtmlEntity().mutate(_make_req(s), rng)
        assert html.unescape(out.payload_text) == s


# --- 4. UnicodeEscape ------------------------------------------------------ #


def test_unicode_escape_golden() -> None:
    req = _make_req("AB")
    out = P.UnicodeEscape().mutate(req, _rng())
    # raw-string: literal backslash + 'u' + 4 hex digits per character.
    assert out.payload_text == "\\u0041\\u0042"


def test_unicode_escape_empty() -> None:
    out = P.UnicodeEscape().mutate(_make_req(""), _rng())
    assert out.payload_text == ""


# --- 5. HexEncode ---------------------------------------------------------- #


def test_hex_encode_golden() -> None:
    req = _make_req("AB")
    out = P.HexEncode().mutate(req, _rng())
    assert out.payload_text == "\\x41\\x42"


def test_hex_encode_unicode() -> None:
    req = _make_req("é")
    out = P.HexEncode().mutate(req, _rng())
    # 'é' UTF-8 = 0xc3 0xa9
    assert out.payload_text == "\\xc3\\xa9"


# --- 6. Base64 ------------------------------------------------------------- #


def test_base64_golden() -> None:
    req = _make_req("AB")
    out = P.Base64Encode().mutate(req, _rng())
    assert out.payload_text == "QUI="


def test_base64_property() -> None:
    for seed in range(50):
        rng = _rng(seed)
        s = "".join(chr(int(rng.integers(32, 127))) for _ in range(20))
        out = P.Base64Encode().mutate(_make_req(s), rng)
        decoded = _b64.b64decode(out.payload_text).decode("utf-8")
        assert decoded == s


# --- 7. CommentInject ------------------------------------------------------ #


def test_comment_inject_determinism() -> None:
    req = _make_req("UNION SELECT")
    a = P.CommentInject().mutate(req, _rng(0))
    b = P.CommentInject().mutate(req, _rng(0))
    assert a.payload_text == b.payload_text


def test_comment_inject_property() -> None:
    base = "UNION SELECT * FROM users"
    for seed in range(50):
        out = P.CommentInject().mutate(_make_req(base), _rng(seed))
        # Если убрать вставленный комментарий, получим исходный.
        cleaned = (
            out.payload_text.replace("/**/", "")
            .replace("/*x*/", "")
            .replace("--+\n", "")
        )
        assert cleaned == base


# --- 8. CaseToggle --------------------------------------------------------- #


def test_case_toggle_golden() -> None:
    req = _make_req("Or 1=1")
    out = P.CaseToggle().mutate(req, _rng())
    assert out.payload_text == "oR 1=1"


def test_case_toggle_property() -> None:
    for seed in range(50):
        rng = _rng(seed)
        s = "".join(chr(int(rng.integers(65, 123))) for _ in range(20))
        out = P.CaseToggle().mutate(_make_req(s), rng)
        assert out.payload_text.lower() == s.lower()


# --- 9. WhitespaceTricks --------------------------------------------------- #


def test_whitespace_tricks_determinism() -> None:
    req = _make_req("OR 1 = 1")
    a = P.WhitespaceTricks().mutate(req, _rng(0))
    b = P.WhitespaceTricks().mutate(req, _rng(0))
    assert a.payload_text == b.payload_text


def test_whitespace_tricks_property() -> None:
    base = "OR 1 = 1 AND 2 = 2"
    for seed in range(50):
        out = P.WhitespaceTricks().mutate(_make_req(base), _rng(seed))
        # Длина не меняется (один whitespace -> один whitespace).
        assert len(out.payload_text) == len(base)
        # Не-пробелы остаются неизменны.
        for orig, new in zip(base, out.payload_text, strict=True):
            if orig != " ":
                assert orig == new


# --- 10. NullByte ---------------------------------------------------------- #


def test_null_byte_golden() -> None:
    req = _make_req("x.txt")
    out = P.NullByte().mutate(req, _rng())
    assert out.payload_text == "x.txt%00"


# --- 11. KeywordFragment --------------------------------------------------- #


def test_keyword_fragment_golden() -> None:
    req = _make_req("UNION SELECT")
    out = P.KeywordFragment().mutate(req, _rng())
    # UN/**/ION SE/**/LECT
    assert out.payload_text == "UN/**/ION SE/**/LECT"


def test_keyword_fragment_no_keywords() -> None:
    req = _make_req("plain text")
    out = P.KeywordFragment().mutate(req, _rng())
    assert out.payload_text == "plain text"


# --- 12. CharsetTrick ------------------------------------------------------ #


def test_charset_trick_golden() -> None:
    req = _make_req("<script>")
    out = P.CharsetTrick().mutate(req, _rng())
    # UTF-7 кодирует <script> детерминированно.
    expected = "<script>".encode("utf-7").decode("ascii")
    assert out.payload_text == expected


def test_charset_trick_empty() -> None:
    out = P.CharsetTrick().mutate(_make_req(""), _rng())
    assert out.payload_text == ""


# --- query-substitution invariant ------------------------------------------ #


def test_query_substitution_when_param_set() -> None:
    req = _make_req("OR 1=1")
    out = P.UrlEncode().mutate(req, _rng())
    assert out.query["id"] == out.payload_text


def test_query_unchanged_when_param_missing() -> None:
    req = _make_req("OR 1=1").with_changes(param_to_fuzz=None)
    out = P.UrlEncode().mutate(req, _rng())
    assert out.query == {"id": "1"}


# --- compatibility: explicit pairs ----------------------------------------- #


@pytest.mark.parametrize(
    ("a", "b", "reason"),
    [
        # Все payload-мутаторы взаимно несовместимы по same-layer-правилу.
        pytest.param(
            "url_encode", "double_url_encode", "same-layer",
            id="url_encode-vs-double_url_encode",
        ),
        pytest.param(
            "html_entity", "base64", "same-layer",
            id="html_entity-vs-base64",
        ),
        pytest.param(
            "case_toggle", "comment_inject", "same-layer",
            id="case_toggle-vs-comment_inject",
        ),
    ],
)
def test_payload_pairs_incompatible(a: str, b: str, reason: str) -> None:
    del reason
    ma = RegistryOfMutators.by_id(a)
    mb = RegistryOfMutators.by_id(b)
    assert not ma.compatible_with(b)  # type: ignore[arg-type]
    assert not mb.compatible_with(a)  # type: ignore[arg-type]


def test_same_layer_pair_random() -> None:
    """Любые два разных payload-мутатора несовместимы (same-layer)."""
    rng = np.random.default_rng(42)
    payload_ids = [m.id for m in RegistryOfMutators.by_layer(Layer.PAYLOAD)]
    a, b = rng.choice(payload_ids, size=2, replace=False).tolist()
    ma = RegistryOfMutators.by_id(a)
    mb = RegistryOfMutators.by_id(b)
    assert not ma.compatible_with(b)
    assert not mb.compatible_with(a)


def test_payload_self_compatible() -> None:
    """Same id with itself is compatible (only one applied per layer)."""
    m = RegistryOfMutators.by_id("url_encode")
    assert m.compatible_with("url_encode")


# --- registration test ----------------------------------------------------- #


def test_payload_registration_complete() -> None:
    expected = {
        "url_encode", "double_url_encode", "html_entity", "unicode_escape",
        "hex_encode", "base64", "comment_inject", "case_toggle",
        "whitespace_tricks", "null_byte", "keyword_fragment", "charset_trick",
    }
    registered = set(RegistryOfMutators.all_ids())
    assert expected <= registered
    for mid in expected:
        m = RegistryOfMutators.by_id(mid)
        assert m.layer is Layer.PAYLOAD
