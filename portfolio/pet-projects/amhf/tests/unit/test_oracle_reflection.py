"""Targeted tests for amhf.oracle.reflection_check.is_xss_reflected.

Stage 6 hygiene — поднимает per-module coverage reflection_check.py
с 68% до ≥70% за счёт явных тестов на каждую ветку детектора:
script-block, event-handler, javascript: URL, html-tag (img/svg/iframe),
plus negative cases (escaped, empty input, payload без спецсимволов).
"""

from __future__ import annotations

from amhf.oracle.reflection_check import is_xss_reflected


def test_empty_payload_returns_false() -> None:
    ok, reason = is_xss_reflected("", "<html>x</html>")
    assert ok is False
    assert reason == ""


def test_empty_body_returns_false() -> None:
    ok, reason = is_xss_reflected("<script>", "")
    assert ok is False
    assert reason == ""


def test_payload_without_special_chars_substring_only() -> None:
    """Payload без <>" — обходимся substring-тестом ветки 37."""
    ok, reason = is_xss_reflected("amhf_xss_marker", "<p>amhf_xss_marker</p>")
    # Отсутствие исполнимого контекста — отражение не подтверждается, но
    # ветка _payload_appears_unescaped возвращает True (line 37).
    assert ok is False
    assert reason == ""


def test_script_block_match() -> None:
    body = "<html><body><script>alert('amhf_xss_marker');</script></body></html>"
    ok, reason = is_xss_reflected("amhf_xss_marker", body)
    assert ok is True
    assert reason == "xss-reflected-in-script-tag"


def test_event_handler_match() -> None:
    body = '<img src=x onerror="alert(1);amhf_xss_marker">'
    ok, reason = is_xss_reflected("amhf_xss_marker", body)
    assert ok is True
    assert reason == "xss-reflected-in-event-handler"


def test_javascript_url_match() -> None:
    body = "<a href=\"javascript:alert(1);amhf_xss_marker\">click</a>"
    ok, reason = is_xss_reflected("amhf_xss_marker", body)
    assert ok is True
    assert reason == "xss-reflected-in-javascript-url"


def test_payload_is_full_script_tag() -> None:
    payload = "<script>alert(1)</script>"
    body = f"<html><body>profile: {payload}</body></html>"
    ok, reason = is_xss_reflected(payload, body)
    assert ok is True
    assert reason == "xss-reflected-as-script-tag"


def test_payload_is_event_handler_attribute() -> None:
    payload = "<img src=x onerror=alert(1)>"
    body = f"<div>{payload}</div>"
    ok, reason = is_xss_reflected(payload, body)
    # Контракт reflection_check: первая успешная ветка возвращается; payload
    # содержит и <img, и onerror=, поэтому может сработать ветка
    # "with-event-handler" (line 77) или "as-html-tag" (line 79). Главное — confirm.
    assert ok is True
    assert reason in {
        "xss-reflected-in-event-handler",
        "xss-reflected-with-event-handler",
        "xss-reflected-as-html-tag",
    }


def test_payload_is_svg_tag() -> None:
    payload = "<svg/onload=alert(1)>"
    body = f"<html>{payload}</html>"
    ok, reason = is_xss_reflected(payload, body)
    assert ok is True
    # Может попасть в event-handler или html-tag — проверяем confirm-факт.
    assert reason


def test_payload_html_escaped_not_confirmed() -> None:
    """WAF block-page: payload присутствует, но html-escape-нут."""
    body = (
        "<html><body><h1>Blocked by WAF</h1>"
        "<p>You sent: &lt;script&gt;alert(1)&lt;/script&gt;</p></body></html>"
    )
    ok, _ = is_xss_reflected("<script>alert(1)</script>", body)
    # Без сырого <script> в body — не подтверждаем.
    assert ok is False


def test_payload_in_text_only_not_confirmed() -> None:
    """Payload в обычном текстовом узле без исполнимого контекста."""
    body = "<html><body>You searched for: <span>alert(1)</span></body></html>"
    ok, _ = is_xss_reflected("alert(1)", body)
    # Substring найден, но не в script/event-handler/js-url → отказ.
    assert ok is False
