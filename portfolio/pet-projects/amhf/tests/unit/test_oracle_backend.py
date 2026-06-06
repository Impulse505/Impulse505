"""Unit tests for BackendOracle (Stage 3) — per attack class."""

from __future__ import annotations

from collections.abc import Callable

from amhf.config import (
    BackendOracleConfig,
    CmdiOracleConfig,
    PathTravOracleConfig,
    SqliOracleConfig,
    XssOracleConfig,
)
from amhf.delivery.request import FuzzResponse
from amhf.oracle.backend_oracle import BackendOracle
from amhf.oracle.timing_oracle import TimingOracle

ResponseFactory = Callable[..., FuzzResponse]


def _backend_cfg() -> BackendOracleConfig:
    return BackendOracleConfig(
        sqli=SqliOracleConfig(
            error_signatures=[
                "You have an error in your SQL syntax",
                "PostgreSQL",
                "ORA-",
                "SQLite",
            ],
            flag_marker="AMHF_FLAG_",
            time_delay_threshold_ms=2500.0,
        ),
        xss=XssOracleConfig(reflection_check=True),
        cmdi=CmdiOracleConfig(command_marker="amhf_cmd_marker"),
        pathtrav=PathTravOracleConfig(canary_marker="amhf_canary_v1"),
    )


# -----------------------------------------------------------------------------
# SQLi
# -----------------------------------------------------------------------------

def test_sqli_error_pattern_matches(sample_response_factory: ResponseFactory) -> None:
    oracle = BackendOracle(_backend_cfg())
    body = "Error: You have an error in your SQL syntax near 'foo'"
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, reason = oracle.confirm(resp, "sqli")
    assert confirmed is True
    assert "sql-error" in reason


def test_sqli_flag_marker_detected(sample_response_factory: ResponseFactory) -> None:
    oracle = BackendOracle(_backend_cfg())
    body = "<html><body>Welcome admin AMHF_FLAG_42abc and goodbye</body></html>"
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, reason = oracle.confirm(resp, "sqli")
    assert confirmed is True
    assert "AMHF_FLAG_" in reason


def test_sqli_benign_body_not_confirmed(sample_response_factory: ResponseFactory) -> None:
    oracle = BackendOracle(_backend_cfg())
    resp = sample_response_factory(status_code=200, body="<html>nothing here</html>")
    confirmed, reason = oracle.confirm(resp, "sqli")
    assert confirmed is False
    assert reason == ""


def test_sqli_time_delay_with_pseudo_marker(
    sample_response_factory: ResponseFactory,
) -> None:
    """Time-based blind SQLi: __TIME_DELAY__ pseudo-marker + slow response."""
    timing = TimingOracle.from_threshold(2000.0)
    oracle = BackendOracle(_backend_cfg(), timing=timing)
    resp = sample_response_factory(
        status_code=200,
        body="ok no payload echo",
        elapsed_ms=3500.0,
    )
    confirmed, reason = oracle.confirm(
        resp,
        "sqli",
        expected_markers=["__TIME_DELAY__"],
    )
    assert confirmed is True
    assert "timing-blind" in reason


def test_sqli_time_delay_without_pseudo_marker_ignored(
    sample_response_factory: ResponseFactory,
) -> None:
    timing = TimingOracle.from_threshold(2000.0)
    oracle = BackendOracle(_backend_cfg(), timing=timing)
    resp = sample_response_factory(status_code=200, body="ok", elapsed_ms=5000.0)
    # Без __TIME_DELAY__ в expected_markers оракул не должен срабатывать.
    confirmed, _ = oracle.confirm(resp, "sqli", expected_markers=[])
    assert confirmed is False


# -----------------------------------------------------------------------------
# XSS
# -----------------------------------------------------------------------------

def test_xss_payload_in_script_tag_confirmed(
    sample_response_factory: ResponseFactory,
) -> None:
    oracle = BackendOracle(_backend_cfg())
    payload = "<script>alert(1)</script>"
    body = f"<html><body>before {payload} after</body></html>"
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, reason = oracle.confirm(resp, "xss", payload_text=payload)
    assert confirmed is True
    assert "xss-reflected" in reason


def test_xss_payload_in_plain_text_not_confirmed(
    sample_response_factory: ResponseFactory,
) -> None:
    """Plain-text reflection without executable context should NOT confirm."""
    oracle = BackendOracle(_backend_cfg())
    payload = "harmless_token"
    body = f"<html><body>echo: {payload} -- but no script context</body></html>"
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, _ = oracle.confirm(resp, "xss", payload_text=payload)
    assert confirmed is False


def test_xss_payload_html_escaped_not_confirmed(
    sample_response_factory: ResponseFactory,
) -> None:
    """If payload appears only HTML-escaped, do NOT confirm."""
    oracle = BackendOracle(_backend_cfg())
    payload = "<script>alert(1)</script>"
    body = (
        "<html><body>echoed: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
    )
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, _ = oracle.confirm(resp, "xss", payload_text=payload)
    assert confirmed is False


def test_xss_event_handler_attribute_confirmed(
    sample_response_factory: ResponseFactory,
) -> None:
    oracle = BackendOracle(_backend_cfg())
    payload = '" onmouseover=alert(1) x="'
    body = f'<input type="text" value="{payload}">'
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, reason = oracle.confirm(resp, "xss", payload_text=payload)
    assert confirmed is True
    assert "xss-reflected" in reason


# -----------------------------------------------------------------------------
# CMDi
# -----------------------------------------------------------------------------

def test_cmdi_command_marker_present(sample_response_factory: ResponseFactory) -> None:
    oracle = BackendOracle(_backend_cfg())
    body = "Output: amhf_cmd_marker on host"
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, reason = oracle.confirm(resp, "cmdi")
    assert confirmed is True
    assert reason == "cmd-marker"


def test_cmdi_uid_heuristic(sample_response_factory: ResponseFactory) -> None:
    oracle = BackendOracle(_backend_cfg())
    body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, reason = oracle.confirm(resp, "cmdi")
    assert confirmed is True
    assert "cmd-heuristic" in reason


def test_cmdi_benign_body_not_confirmed(sample_response_factory: ResponseFactory) -> None:
    oracle = BackendOracle(_backend_cfg())
    resp = sample_response_factory(status_code=200, body="<html>nothing</html>")
    confirmed, _ = oracle.confirm(resp, "cmdi")
    assert confirmed is False


# -----------------------------------------------------------------------------
# PathTrav
# -----------------------------------------------------------------------------

def test_pathtrav_canary_marker_present(sample_response_factory: ResponseFactory) -> None:
    oracle = BackendOracle(_backend_cfg())
    body = "file content: amhf_canary_v1\nend"
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, reason = oracle.confirm(resp, "pathtrav")
    assert confirmed is True
    assert reason == "canary-marker"


def test_pathtrav_passwd_content(sample_response_factory: ResponseFactory) -> None:
    oracle = BackendOracle(_backend_cfg())
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    resp = sample_response_factory(status_code=200, body=body)
    confirmed, reason = oracle.confirm(resp, "pathtrav")
    assert confirmed is True
    assert "passwd-marker" in reason


def test_pathtrav_benign_body_not_confirmed(sample_response_factory: ResponseFactory) -> None:
    oracle = BackendOracle(_backend_cfg())
    resp = sample_response_factory(status_code=200, body="404 Not Found")
    confirmed, _ = oracle.confirm(resp, "pathtrav")
    assert confirmed is False


def test_unknown_attack_class_returns_false(
    sample_response_factory: ResponseFactory,
) -> None:
    oracle = BackendOracle(_backend_cfg())
    resp = sample_response_factory(status_code=200, body="x")
    confirmed, reason = oracle.confirm(resp, "ssrf")
    assert confirmed is False
    assert "unknown attack_class" in reason
