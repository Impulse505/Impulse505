"""Unit tests for amhf.mutators.body — 7 mutators."""

from __future__ import annotations

import gzip
import json

import numpy as np
import pytest

import amhf.mutators  # noqa: F401  (ensure registration)
from amhf.delivery.request import FuzzRequest
from amhf.mutators import body as B  # noqa: N812 (single-letter alias for tests)
from amhf.mutators.base import Layer, MutationSkipped, RegistryOfMutators


def _form_req(body: bytes = b"id=1&page=2") -> FuzzRequest:
    return FuzzRequest(
        method="POST",
        url="http://localhost/vuln",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        query={},
        body_bytes=body,
        attack_class="sqli",
        payload_id="t1",
        payload_text="' OR 1=1",
        param_to_fuzz="id",
    )


def _rng(seed: int = 0) -> np.random.Generator:
    return np.random.default_rng(seed)


# --- 1. MultipartBoundary -------------------------------------------------- #


def test_multipart_boundary_determinism() -> None:
    req = _form_req()
    a = B.MultipartBoundary().mutate(req, _rng(0))
    b = B.MultipartBoundary().mutate(req, _rng(0))
    assert a.body_bytes == b.body_bytes
    assert a.headers["Content-Type"] == b.headers["Content-Type"]


def test_multipart_boundary_property() -> None:
    """Парсим обратно multipart и восстанавливаем поля."""
    req = _form_req(b"id=42&page=hello")
    for seed in range(50):
        out = B.MultipartBoundary().mutate(req, _rng(seed))
        ct = out.headers["Content-Type"]
        assert ct.startswith("multipart/form-data; boundary=")
        boundary = ct.split("boundary=", 1)[1]
        # Проверяем структуру: --boundary, Content-Disposition, --boundary--.
        body = out.body_bytes.decode("utf-8")
        assert f"--{boundary}\r\n" in body
        assert f"--{boundary}--\r\n" in body
        # Каждый параметр (id, page) появляется ровно один раз.
        assert body.count('name="id"') == 1
        assert body.count('name="page"') == 1
        # Значения сохраняются.
        assert "42" in body
        assert "hello" in body


def test_multipart_boundary_empty_body_skipped() -> None:
    req = _form_req(b"").with_changes(param_to_fuzz=None)
    with pytest.raises(MutationSkipped):
        B.MultipartBoundary().mutate(req, _rng())


# --- 2. CharsetJuggle ------------------------------------------------------ #


def test_charset_juggle_golden() -> None:
    req = _form_req()
    out = B.CharsetJuggle().mutate(req, _rng())
    assert out.headers["Content-Type"] == (
        "application/x-www-form-urlencoded; charset=ibm500"
    )


def test_charset_juggle_replaces_existing_charset() -> None:
    req = _form_req().with_changes(
        headers={"Content-Type": "text/plain; charset=utf-8"}
    )
    out = B.CharsetJuggle().mutate(req, _rng())
    assert out.headers["Content-Type"] == "text/plain; charset=ibm500"


# --- 3. ParamPollution ----------------------------------------------------- #


def test_param_pollution_golden() -> None:
    req = _form_req(b"id=1")
    out = B.ParamPollution().mutate(req, _rng())
    body = out.body_bytes.decode("utf-8")
    assert body.count("id=") == 2
    assert "id=1" in body
    assert "id=%27%20OR%201%3D1" in body


def test_param_pollution_no_param_skipped() -> None:
    req = _form_req(b"id=1").with_changes(param_to_fuzz=None)
    with pytest.raises(MutationSkipped):
        B.ParamPollution().mutate(req, _rng())


def test_param_pollution_long_input() -> None:
    long_payload = "x" * 8192
    req = _form_req(b"id=1").with_changes(payload_text=long_payload)
    out = B.ParamPollution().mutate(req, _rng())
    assert long_payload in out.body_bytes.decode("utf-8")


# --- 4. JsonFormSwap ------------------------------------------------------- #


def test_json_form_swap_golden() -> None:
    req = _form_req(b"id=1&page=2")
    out = B.JsonFormSwap().mutate(req, _rng())
    parsed = json.loads(out.body_bytes)
    assert parsed == {"id": "1", "page": "2"}
    assert out.headers["Content-Type"] == "application/json"


def test_json_form_swap_empty_skipped() -> None:
    req = _form_req(b"").with_changes(param_to_fuzz=None)
    with pytest.raises(MutationSkipped):
        B.JsonFormSwap().mutate(req, _rng())


# --- 5. ContentTypeSwap ---------------------------------------------------- #


def test_content_type_swap_golden() -> None:
    req = _form_req()
    out = B.ContentTypeSwap().mutate(req, _rng())
    assert out.headers["Content-Type"] == "text/plain"
    # Тело не трогаем.
    assert out.body_bytes == req.body_bytes


# --- 6. GzipEncode --------------------------------------------------------- #


def test_gzip_encode_roundtrip() -> None:
    req = _form_req(b"id=1&page=2")
    out = B.GzipEncode().mutate(req, _rng())
    assert out.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(out.body_bytes) == b"id=1&page=2"


def test_gzip_encode_long_input() -> None:
    payload = b"a" * 8192
    req = _form_req(payload)
    out = B.GzipEncode().mutate(req, _rng())
    assert gzip.decompress(out.body_bytes) == payload
    # Сжатие действительно сократило тело.
    assert len(out.body_bytes) < len(payload)


# --- 7. ChunkedEncode ------------------------------------------------------ #


def test_chunked_encode_golden() -> None:
    req = _form_req(b"id=1")
    out = B.ChunkedEncode().mutate(req, _rng())
    assert out.headers["Transfer-Encoding"] == "chunked"
    # 4 hex-байт + CRLF + body + CRLF + 0 + CRLF + CRLF.
    assert out.body_bytes == b"4\r\nid=1\r\n0\r\n\r\n"


def test_chunked_encode_removes_content_length() -> None:
    req = _form_req(b"id=1").with_changes(
        headers={"Content-Type": "x", "Content-Length": "4"}
    )
    out = B.ChunkedEncode().mutate(req, _rng())
    assert "Content-Length" not in out.headers


# --- compatibility: explicit pairs ----------------------------------------- #


@pytest.mark.parametrize(
    ("a", "b", "reason"),
    [
        pytest.param(
            "json_form_swap", "multipart_boundary", "different-body-structures",
            id="json_form_swap-vs-multipart_boundary",
        ),
        pytest.param(
            "json_form_swap", "param_pollution", "different-body-structures",
            id="json_form_swap-vs-param_pollution",
        ),
        pytest.param(
            "json_form_swap", "content_type_swap", "both-rewrite-content-type",
            id="json_form_swap-vs-content_type_swap",
        ),
        pytest.param(
            "gzip_encode", "chunked_encode", "combined-behaviour-unspecified",
            id="gzip_encode-vs-chunked_encode",
        ),
    ],
)
def test_body_pairs_incompatible(a: str, b: str, reason: str) -> None:
    del reason
    ma = RegistryOfMutators.by_id(a)
    mb = RegistryOfMutators.by_id(b)
    assert not ma.compatible_with(b)  # type: ignore[arg-type]
    assert not mb.compatible_with(a)  # type: ignore[arg-type]


def test_same_layer_pair_random_body() -> None:
    rng = np.random.default_rng(7)
    body_ids = [m.id for m in RegistryOfMutators.by_layer(Layer.BODY)]
    a, b = rng.choice(body_ids, size=2, replace=False).tolist()
    ma = RegistryOfMutators.by_id(a)
    mb = RegistryOfMutators.by_id(b)
    assert not ma.compatible_with(b)
    assert not mb.compatible_with(a)


# --- registration test ----------------------------------------------------- #


def test_body_registration_complete() -> None:
    expected = {
        "multipart_boundary", "charset_juggle", "param_pollution",
        "json_form_swap", "content_type_swap", "gzip_encode", "chunked_encode",
    }
    registered = set(RegistryOfMutators.all_ids())
    assert expected <= registered
    for mid in expected:
        m = RegistryOfMutators.by_id(mid)
        assert m.layer is Layer.BODY
