"""XSS reflection helper — проверка отражения payload в *исполнимом* контексте.

Наивная проверка ``payload in body`` даёт слишком много ложных срабатываний:
WAF-page и текстовое поле могут содержать echo payload без возможности
исполнения. Поэтому здесь поверх substring-теста проверяется HTML-контекст:
блок ``<script>``, обработчик события (``onXxx="..."``), либо
``javascript:``-URL.

Возвращаемое значение — кортеж ``(reflected, reason)``. Если payload не
найден или найден только в HTML-escape-форме, возвращается ``(False, "")``.
"""

from __future__ import annotations

import re

# Регулярки скомпилированы один раз — повторное использование в hot-path.
_SCRIPT_BLOCK_RE = re.compile(
    r"<script\b[^>]*>(.*?)</script\s*>",
    re.IGNORECASE | re.DOTALL,
)
_EVENT_HANDLER_RE = re.compile(
    r"\son[a-z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)",
    re.IGNORECASE,
)
_JAVASCRIPT_URL_RE = re.compile(
    r"(?:href|src)\s*=\s*(?:\"javascript:[^\"]*\"|'javascript:[^']*'|javascript:[^\s>]+)",
    re.IGNORECASE,
)


def _payload_appears_unescaped(payload: str, body: str) -> bool:
    """Хотя бы один ключевой символ payload присутствует в body не html-escape-нутым."""
    interesting = [c for c in ("<", ">", "\"") if c in payload]
    if not interesting:
        # Payload без спецсимволов — самим substring-тестом обойдёмся.
        return payload in body
    # Если payload присутствует целиком как substring — этого достаточно.
    if payload in body:
        return True
    # Иначе проверяем, что хотя бы какой-то ключевой символ виден неэскейпленным.
    return any(c in body for c in interesting)


def is_xss_reflected(payload: str, body: str) -> tuple[bool, str]:
    """True, если payload отражён в исполнимом HTML-контексте."""
    if not payload or not body:
        return (False, "")

    # Если payload присутствует только в html-escape-варианте — не исполнимо.
    if payload not in body and not _payload_appears_unescaped(payload, body):
        # Полностью эскейп-нуто либо вообще не отражён — не подтверждаем.
        return (False, "")

    # 1) Внутри <script>...</script>
    for match in _SCRIPT_BLOCK_RE.finditer(body):
        if payload in match.group(1):
            return (True, "xss-reflected-in-script-tag")

    # 2) Внутри обработчика события onXxx="..."
    for match in _EVENT_HANDLER_RE.finditer(body):
        if payload in match.group(0):
            return (True, "xss-reflected-in-event-handler")

    # 3) javascript: URL в href/src
    for match in _JAVASCRIPT_URL_RE.finditer(body):
        if payload in match.group(0):
            return (True, "xss-reflected-in-javascript-url")

    # 4) Сам payload содержит свой собственный <script>-блок — частый случай,
    # когда payload отрисован в HTML вне script, но представляет собой целый
    # тег. В этом случае хотим подтвердить отражение, если payload-подстрока
    # сама содержит исполнимую конструкцию.
    if "<script" in payload.lower() and payload in body:
        return (True, "xss-reflected-as-script-tag")
    if re.search(r"\son[a-z]+\s*=", payload, re.IGNORECASE) and payload in body:
        return (True, "xss-reflected-with-event-handler")
    if re.search(r"<\s*(img|svg|iframe)\b", payload, re.IGNORECASE) and payload in body:
        return (True, "xss-reflected-as-html-tag")

    return (False, "")
