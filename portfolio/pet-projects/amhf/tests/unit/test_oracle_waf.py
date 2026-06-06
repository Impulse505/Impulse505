"""Unit tests for WafOracle (Stage 3)."""

from __future__ import annotations

from collections.abc import Callable

from amhf.config import WafOracleConfig
from amhf.delivery.request import FuzzResponse
from amhf.oracle.waf_oracle import WafOracle

ResponseFactory = Callable[..., FuzzResponse]


def _cfg(
    *,
    blocked_codes: list[int] | None = None,
    signatures: list[str] | None = None,
    block_page_size_max: int = 4096,
) -> WafOracleConfig:
    return WafOracleConfig(
        blocked_codes=blocked_codes if blocked_codes is not None else [403, 406],
        blocked_body_signatures=(
            signatures
            if signatures is not None
            else ["ModSecurity", "NAXSI", "Nemesida WAF"]
        ),
        block_page_size_max=block_page_size_max,
    )


def test_403_empty_body_blocked(sample_response_factory: ResponseFactory) -> None:
    oracle = WafOracle(_cfg())
    resp = sample_response_factory(status_code=403, body="")
    blocked, sig = oracle.is_blocked(resp)
    assert blocked is True
    assert sig == "http_403"


def test_200_with_modsecurity_signature_blocked(
    sample_response_factory: ResponseFactory,
) -> None:
    oracle = WafOracle(_cfg())
    body = "<html><body>Blocked by ModSecurity rule</body></html>"
    resp = sample_response_factory(status_code=200, body=body)
    blocked, sig = oracle.is_blocked(resp)
    assert blocked is True
    assert sig == "ModSecurity"


def test_200_no_signature_not_blocked(
    sample_response_factory: ResponseFactory,
) -> None:
    oracle = WafOracle(_cfg())
    resp = sample_response_factory(status_code=200, body="ordinary response with no waf hint")
    blocked, sig = oracle.is_blocked(resp)
    assert blocked is False
    assert sig is None


def test_200_with_signature_in_large_body_not_blocked(
    sample_response_factory: ResponseFactory,
) -> None:
    """Body > block_page_size_max: signature is treated as echo, not block-page."""
    oracle = WafOracle(_cfg(block_page_size_max=4096))
    # 8 KB body containing the signature (way above block_page_size_max=4096).
    body = "NAXSI" + ("x" * 8192)
    resp = sample_response_factory(status_code=200, body=body)
    blocked, sig = oracle.is_blocked(resp)
    assert blocked is False
    assert sig is None


def test_500_no_signature_not_blocked(
    sample_response_factory: ResponseFactory,
) -> None:
    """Server-error responses are NOT WAF-blocks (CombinedOracle handles separately)."""
    oracle = WafOracle(_cfg())
    resp = sample_response_factory(status_code=500, body="Internal Server Error")
    blocked, sig = oracle.is_blocked(resp)
    assert blocked is False
    assert sig is None


def test_5xx_with_signature_still_not_waf_block(
    sample_response_factory: ResponseFactory,
) -> None:
    """5xx is server_error, not waf_block — even if signature is present."""
    oracle = WafOracle(_cfg())
    resp = sample_response_factory(status_code=503, body="ModSecurity engine off")
    blocked, sig = oracle.is_blocked(resp)
    assert blocked is False
    assert sig is None


def test_transport_error_not_blocked(sample_response_factory: ResponseFactory) -> None:
    """Transport errors are not classified as WAF blocks."""
    oracle = WafOracle(_cfg())
    resp = sample_response_factory(status_code=0, body="", error="ConnectTimeout")
    blocked, sig = oracle.is_blocked(resp)
    assert blocked is False
    assert sig is None


def test_blocked_code_takes_precedence_over_signature(
    sample_response_factory: ResponseFactory,
) -> None:
    """If status_code is in blocked_codes, that wins (signature='http_<code>')."""
    oracle = WafOracle(_cfg())
    resp = sample_response_factory(status_code=403, body="ModSecurity blocked you")
    blocked, sig = oracle.is_blocked(resp)
    assert blocked is True
    assert sig == "http_403"


def test_signature_match_is_case_sensitive(
    sample_response_factory: ResponseFactory,
) -> None:
    """Signature match must be case-sensitive (per spec)."""
    oracle = WafOracle(_cfg(signatures=["ModSecurity"]))
    resp = sample_response_factory(status_code=200, body="modsecurity (lowercase)")
    blocked, sig = oracle.is_blocked(resp)
    assert blocked is False
    assert sig is None
