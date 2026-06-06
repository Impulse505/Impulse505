"""Unit tests for amhf.mutators.headers — 6 mutators."""

from __future__ import annotations

import ipaddress

import numpy as np
import pytest

import amhf.mutators  # noqa: F401  (ensure registration)
from amhf.delivery.request import FuzzRequest
from amhf.mutators import headers as H  # noqa: N812 (single-letter alias for tests)
from amhf.mutators.base import Layer, RegistryOfMutators


def _req() -> FuzzRequest:
    return FuzzRequest(
        method="GET",
        url="http://localhost/vuln?id=1",
        headers={"Host": "localhost", "User-Agent": "amhf/test"},
        query={"id": "1"},
        body_bytes=b"",
        attack_class="sqli",
        payload_id="t1",
        payload_text="' OR 1=1",
        param_to_fuzz="id",
    )


def _rng(seed: int = 0) -> np.random.Generator:
    return np.random.default_rng(seed)


# --- 1. Duplicate ---------------------------------------------------------- #


def test_duplicate_golden() -> None:
    out = H.Duplicate().mutate(_req(), _rng())
    assert out.headers["X-Original-URL"] == "/vuln?id=1"


def test_duplicate_no_query() -> None:
    req = _req().with_changes(url="http://localhost/vuln")
    out = H.Duplicate().mutate(req, _rng())
    assert out.headers["X-Original-URL"] == "/vuln"


# --- 2. CaseJiggle --------------------------------------------------------- #


def test_case_jiggle_determinism() -> None:
    a = H.CaseJiggle().mutate(_req(), _rng(0))
    b = H.CaseJiggle().mutate(_req(), _rng(0))
    assert a.headers == b.headers


def test_case_jiggle_property() -> None:
    """Имена меняются по регистру; case-insensitive структура сохраняется."""
    for seed in range(50):
        out = H.CaseJiggle().mutate(_req(), _rng(seed))
        # Все имена сохранили длину и совпадают case-insensitive с исходными.
        original_lower = {k.lower() for k in _req().headers}
        out_lower = {k.lower() for k in out.headers}
        assert original_lower == out_lower
        # Значения остались неизменны.
        for k, v in out.headers.items():
            # ищем оригинальное значение по case-insensitive имени.
            orig_v = next(
                ov for ok, ov in _req().headers.items() if ok.lower() == k.lower()
            )
            assert v == orig_v


# --- 3. TransferEncodingCollision ------------------------------------------ #


def test_transfer_encoding_collision_golden() -> None:
    out = H.TransferEncodingCollision().mutate(_req(), _rng())
    assert out.headers["Transfer-Encoding"] == "chunked, identity"


# --- 4. XffSpoof ----------------------------------------------------------- #


def test_xff_spoof_determinism() -> None:
    a = H.XffSpoof().mutate(_req(), _rng(0))
    b = H.XffSpoof().mutate(_req(), _rng(0))
    assert a.headers["X-Forwarded-For"] == b.headers["X-Forwarded-For"]


def test_xff_spoof_property() -> None:
    """Output is always a valid RFC1918 IPv4 address."""
    for seed in range(50):
        out = H.XffSpoof().mutate(_req(), _rng(seed))
        ip = ipaddress.IPv4Address(out.headers["X-Forwarded-For"])
        assert ip.is_private


# --- 5. AcceptEncodingTrick ------------------------------------------------ #


def test_accept_encoding_trick_golden() -> None:
    out = H.AcceptEncodingTrick().mutate(_req(), _rng())
    assert out.headers["Accept-Encoding"] == "identity;q=0,*;q=1"


# --- 6. HostHeaderTrick ---------------------------------------------------- #


def test_host_header_trick_golden() -> None:
    out = H.HostHeaderTrick().mutate(_req(), _rng())
    assert out.headers["X-Forwarded-Host"] == "evil.example"
    # Оригинальный Host остаётся без изменений.
    assert out.headers["Host"] == "localhost"


# --- compatibility: explicit pairs ----------------------------------------- #


@pytest.mark.parametrize(
    ("a", "b", "reason"),
    [
        pytest.param(
            "duplicate", "case_jiggle", "same-layer",
            id="duplicate-vs-case_jiggle",
        ),
        pytest.param(
            "xff_spoof", "host_header_trick", "same-layer",
            id="xff_spoof-vs-host_header_trick",
        ),
        pytest.param(
            "transfer_encoding_collision", "accept_encoding_trick", "same-layer",
            id="te_collision-vs-ae_trick",
        ),
    ],
)
def test_headers_pairs_incompatible(a: str, b: str, reason: str) -> None:
    del reason
    ma = RegistryOfMutators.by_id(a)
    mb = RegistryOfMutators.by_id(b)
    assert not ma.compatible_with(b)  # type: ignore[arg-type]
    assert not mb.compatible_with(a)  # type: ignore[arg-type]


def test_same_layer_pair_random_headers() -> None:
    rng = np.random.default_rng(11)
    hdr_ids = [m.id for m in RegistryOfMutators.by_layer(Layer.HEADERS)]
    a, b = rng.choice(hdr_ids, size=2, replace=False).tolist()
    ma = RegistryOfMutators.by_id(a)
    mb = RegistryOfMutators.by_id(b)
    assert not ma.compatible_with(b)
    assert not mb.compatible_with(a)


def test_headers_cross_layer_compatible() -> None:
    """Headers-mutator совместим с любым мутатором другого слоя."""
    h = RegistryOfMutators.by_id("duplicate")
    assert h.compatible_with("url_encode")  # payload-layer
    assert h.compatible_with("gzip_encode")  # body-layer
    assert h.compatible_with("path_normalize")  # url-layer


# --- registration test ----------------------------------------------------- #


def test_headers_registration_complete() -> None:
    expected = {
        "duplicate", "case_jiggle", "transfer_encoding_collision",
        "xff_spoof", "accept_encoding_trick", "host_header_trick",
    }
    registered = set(RegistryOfMutators.all_ids())
    assert expected <= registered
    for mid in expected:
        m = RegistryOfMutators.by_id(mid)
        assert m.layer is Layer.HEADERS
