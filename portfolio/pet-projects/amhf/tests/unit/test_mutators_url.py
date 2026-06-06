"""Unit tests for amhf.mutators.url — 6 mutators."""

from __future__ import annotations

import urllib.parse

import numpy as np
import pytest

import amhf.mutators  # noqa: F401  (ensure registration)
from amhf.delivery.request import FuzzRequest
from amhf.mutators import url as U  # noqa: N812 (single-letter alias for tests)
from amhf.mutators.base import Layer, RegistryOfMutators


def _req() -> FuzzRequest:
    return FuzzRequest(
        method="GET",
        url="http://localhost/vuln?id=1",
        headers={},
        query={"id": "1"},
        body_bytes=b"",
        attack_class="sqli",
        payload_id="t1",
        payload_text="' OR 1=1",
        param_to_fuzz="id",
    )


def _rng(seed: int = 0) -> np.random.Generator:
    return np.random.default_rng(seed)


# --- 1. MethodCase --------------------------------------------------------- #


def test_method_case_golden() -> None:
    out = U.MethodCase().mutate(_req(), _rng())
    assert out.method == "Get"


def test_method_case_post() -> None:
    out = U.MethodCase().mutate(_req().with_changes(method="POST"), _rng())
    assert out.method == "Post"


# --- 2. PathNormalize ------------------------------------------------------ #


def test_path_normalize_golden() -> None:
    out = U.PathNormalize().mutate(_req(), _rng())
    sp = urllib.parse.urlsplit(out.url)
    assert sp.path == "/a/../vuln"
    # query preserved.
    assert sp.query == "id=1"


def test_path_normalize_long_path() -> None:
    long_path = "/" + "a/" * 4000  # 8001-byte path
    req = _req().with_changes(url=f"http://localhost{long_path}")
    out = U.PathNormalize().mutate(req, _rng())
    assert "/a/.." in out.url


# --- 3. PercentEncodePath -------------------------------------------------- #


def test_percent_encode_path_golden() -> None:
    out = U.PercentEncodePath().mutate(_req(), _rng())
    sp = urllib.parse.urlsplit(out.url)
    assert sp.path == "/%76%75%6c%6e"
    assert sp.query == "id=1"


def test_percent_encode_path_decodes_back() -> None:
    out = U.PercentEncodePath().mutate(_req(), _rng())
    sp = urllib.parse.urlsplit(out.url)
    assert urllib.parse.unquote(sp.path) == "/vuln"


def test_percent_encode_path_unicode() -> None:
    req = _req().with_changes(url="http://localhost/файл")
    out = U.PercentEncodePath().mutate(req, _rng())
    sp = urllib.parse.urlsplit(out.url)
    assert urllib.parse.unquote(sp.path) == "/файл"


# --- 4. SegmentInject ------------------------------------------------------ #


def test_segment_inject_determinism() -> None:
    a = U.SegmentInject().mutate(_req(), _rng(0))
    b = U.SegmentInject().mutate(_req(), _rng(0))
    assert a.url == b.url


def test_segment_inject_property() -> None:
    """Inserted matrix-param contains exactly 8 ASCII upper-case letters."""
    for seed in range(50):
        out = U.SegmentInject().mutate(_req(), _rng(seed))
        sp = urllib.parse.urlsplit(out.url)
        assert ";jsessionid=" in sp.path
        token = sp.path.split(";jsessionid=", 1)[1]
        assert len(token) == 8
        assert all(c.isupper() and c.isalpha() for c in token)


# --- 5. FragmentInject ----------------------------------------------------- #


def test_fragment_inject_golden() -> None:
    out = U.FragmentInject().mutate(_req(), _rng())
    sp = urllib.parse.urlsplit(out.url)
    assert sp.fragment == "amhf"
    # Path/query untouched.
    assert sp.path == "/vuln"
    assert sp.query == "id=1"


# --- 6. QueryEncoding ------------------------------------------------------ #


def test_query_encoding_golden() -> None:
    out = U.QueryEncoding().mutate(_req(), _rng())
    sp = urllib.parse.urlsplit(out.url)
    assert sp.query == "%69%64=%31"


def test_query_encoding_roundtrip() -> None:
    req = _req().with_changes(url="http://localhost/x?a=1&b=hello")
    out = U.QueryEncoding().mutate(req, _rng())
    sp = urllib.parse.urlsplit(out.url)
    pairs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
    # decode даёт исходные пары.
    assert pairs == [("a", "1"), ("b", "hello")]


def test_query_encoding_long_value() -> None:
    long_v = "x" * 8000
    req = _req().with_changes(url=f"http://localhost/x?a={long_v}")
    out = U.QueryEncoding().mutate(req, _rng())
    sp = urllib.parse.urlsplit(out.url)
    pairs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
    assert pairs == [("a", long_v)]


# --- compatibility: explicit pairs ----------------------------------------- #


@pytest.mark.parametrize(
    ("a", "b", "reason"),
    [
        pytest.param(
            "method_case", "path_normalize", "same-layer",
            id="method_case-vs-path_normalize",
        ),
        pytest.param(
            "percent_encode_path", "query_encoding", "same-layer",
            id="percent_encode_path-vs-query_encoding",
        ),
        pytest.param(
            "segment_inject", "fragment_inject", "same-layer",
            id="segment_inject-vs-fragment_inject",
        ),
    ],
)
def test_url_pairs_incompatible(a: str, b: str, reason: str) -> None:
    del reason
    ma = RegistryOfMutators.by_id(a)
    mb = RegistryOfMutators.by_id(b)
    assert not ma.compatible_with(b)  # type: ignore[arg-type]
    assert not mb.compatible_with(a)  # type: ignore[arg-type]


def test_same_layer_pair_random_url() -> None:
    rng = np.random.default_rng(13)
    url_ids = [m.id for m in RegistryOfMutators.by_layer(Layer.URL)]
    a, b = rng.choice(url_ids, size=2, replace=False).tolist()
    ma = RegistryOfMutators.by_id(a)
    mb = RegistryOfMutators.by_id(b)
    assert not ma.compatible_with(b)
    assert not mb.compatible_with(a)


def test_url_cross_layer_compatible() -> None:
    """URL-mutator совместим с любым мутатором другого слоя."""
    u = RegistryOfMutators.by_id("path_normalize")
    assert u.compatible_with("url_encode")  # payload
    assert u.compatible_with("gzip_encode")  # body
    assert u.compatible_with("xff_spoof")    # headers


# --- registration test ----------------------------------------------------- #


def test_url_registration_complete() -> None:
    expected = {
        "method_case", "path_normalize", "percent_encode_path",
        "segment_inject", "fragment_inject", "query_encoding",
    }
    registered = set(RegistryOfMutators.all_ids())
    assert expected <= registered
    for mid in expected:
        m = RegistryOfMutators.by_id(mid)
        assert m.layer is Layer.URL
