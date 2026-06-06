"""Unit tests for CombinedOracle (Stage 3)."""

from __future__ import annotations

from collections.abc import Callable

from amhf.config import (
    BackendOracleConfig,
    CmdiOracleConfig,
    OracleConfig,
    PathTravOracleConfig,
    SqliOracleConfig,
    WafOracleConfig,
    XssOracleConfig,
)
from amhf.delivery.request import FuzzResponse
from amhf.oracle.combined import CombinedOracle, OracleReason

ResponseFactory = Callable[..., FuzzResponse]


def _oracle_cfg() -> OracleConfig:
    return OracleConfig(
        waf=WafOracleConfig(
            blocked_codes=[403, 406, 501, 418, 419],
            blocked_body_signatures=["ModSecurity", "NAXSI", "Nemesida WAF"],
            block_page_size_max=4096,
        ),
        backend=BackendOracleConfig(
            sqli=SqliOracleConfig(
                error_signatures=[
                    "You have an error in your SQL syntax",
                    "PostgreSQL",
                ],
                flag_marker="AMHF_FLAG_",
                time_delay_threshold_ms=2500.0,
            ),
            xss=XssOracleConfig(reflection_check=True),
            cmdi=CmdiOracleConfig(command_marker="amhf_cmd_marker"),
            pathtrav=PathTravOracleConfig(canary_marker="amhf_canary_v1"),
        ),
    )


def test_waf_block_with_payload_reflection_no_xss_confirm(
    sample_response_factory: ResponseFactory,
) -> None:
    """KEY TRAP: payload reflected inside WAF block-page must NOT confirm XSS."""
    oracle = CombinedOracle(_oracle_cfg())
    payload = "<script>alert(1)</script>"
    body = (
        "<html><body><h1>Blocked by ModSecurity</h1>"
        "<p>You sent: <script>alert(1)</script></p>"
        "</body></html>"
    )
    resp = sample_response_factory(status_code=403, body=body)
    verdict = oracle.evaluate(resp, "xss", payload_text=payload)
    assert verdict.bypass is False
    assert verdict.waf_blocked is True
    assert verdict.exploit_confirmed is False
    assert verdict.reason == OracleReason.WAF_BLOCKED
    assert verdict.waf_signature_hit == "http_403"


def test_no_waf_no_exploit_returns_no_exploit(
    sample_response_factory: ResponseFactory,
) -> None:
    oracle = CombinedOracle(_oracle_cfg())
    resp = sample_response_factory(status_code=200, body="<html>nothing</html>")
    verdict = oracle.evaluate(resp, "sqli")
    assert verdict.bypass is False
    assert verdict.waf_blocked is False
    assert verdict.exploit_confirmed is False
    assert verdict.reason == OracleReason.NO_EXPLOIT


def test_sqli_flag_marker_yields_exploit_confirmed(
    sample_response_factory: ResponseFactory,
) -> None:
    oracle = CombinedOracle(_oracle_cfg())
    body = "<html>Welcome admin AMHF_FLAG_42 enjoy</html>"
    resp = sample_response_factory(status_code=200, body=body)
    verdict = oracle.evaluate(resp, "sqli")
    assert verdict.bypass is True
    assert verdict.exploit_confirmed is True
    assert verdict.waf_blocked is False
    assert verdict.reason == OracleReason.EXPLOIT_CONFIRMED
    assert "AMHF_FLAG_" in verdict.detail


def test_503_classified_as_server_error(
    sample_response_factory: ResponseFactory,
) -> None:
    oracle = CombinedOracle(_oracle_cfg())
    resp = sample_response_factory(status_code=503, body="Service Unavailable")
    verdict = oracle.evaluate(resp, "sqli")
    assert verdict.bypass is False
    assert verdict.server_error is True
    assert verdict.waf_blocked is False
    assert verdict.reason == OracleReason.SERVER_ERROR


def test_transport_error_classified(
    sample_response_factory: ResponseFactory,
) -> None:
    oracle = CombinedOracle(_oracle_cfg())
    resp = sample_response_factory(
        status_code=0,
        body="",
        error="ConnectTimeout: target refused",
    )
    verdict = oracle.evaluate(resp, "xss", payload_text="<script>alert(1)</script>")
    assert verdict.bypass is False
    assert verdict.waf_blocked is False
    assert verdict.exploit_confirmed is False
    assert verdict.reason == OracleReason.TRANSPORT_ERROR
    assert "ConnectTimeout" in verdict.detail


def test_xss_genuine_bypass(sample_response_factory: ResponseFactory) -> None:
    """Genuine XSS bypass: payload echoed inside <script> with no WAF block."""
    oracle = CombinedOracle(_oracle_cfg())
    payload = "<script>alert(1)</script>"
    body = f"<html><body>profile: {payload}</body></html>"
    resp = sample_response_factory(status_code=200, body=body)
    verdict = oracle.evaluate(resp, "xss", payload_text=payload)
    assert verdict.bypass is True
    assert verdict.exploit_confirmed is True
    assert verdict.reason == OracleReason.EXPLOIT_CONFIRMED


def test_modsec_200_block_page(sample_response_factory: ResponseFactory) -> None:
    """ModSec 200 block page (small body + signature) → WAF_BLOCKED."""
    oracle = CombinedOracle(_oracle_cfg())
    body = "<html>Blocked by ModSecurity</html>"
    resp = sample_response_factory(status_code=200, body=body)
    verdict = oracle.evaluate(resp, "sqli")
    assert verdict.waf_blocked is True
    assert verdict.reason == OracleReason.WAF_BLOCKED
    assert verdict.waf_signature_hit == "ModSecurity"


def test_pathtrav_canary_bypass(sample_response_factory: ResponseFactory) -> None:
    oracle = CombinedOracle(_oracle_cfg())
    body = "amhf_canary_v1\n"
    resp = sample_response_factory(status_code=200, body=body)
    verdict = oracle.evaluate(resp, "pathtrav")
    assert verdict.bypass is True
    assert verdict.detail == "canary-marker"


def test_cmdi_marker_bypass(sample_response_factory: ResponseFactory) -> None:
    oracle = CombinedOracle(_oracle_cfg())
    body = "$ id\namhf_cmd_marker"
    resp = sample_response_factory(status_code=200, body=body)
    verdict = oracle.evaluate(resp, "cmdi")
    assert verdict.bypass is True
    assert verdict.exploit_confirmed is True
    assert verdict.detail == "cmd-marker"
