"""AsyncHTTPClient — тонкая обёртка над aiohttp для слоя доставки AMHF.

Особенности:
- ``allow_redirects=False`` — многие WAF возвращают 302 на блок-страницу,
  и автоматический редирект скрыл бы факт блокировки.
- Ретраи только на транспортных ошибках; HTTP 4xx/5xx — это сигнал
  оракула, его трогать нельзя.
- Семафор ограничивает параллелизм; ленивый токен-бакет — RPS.
- Тело ответа декодируется по charset из ``Content-Type``; fallback —
  utf-8 (errors=replace), затем latin-1.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from types import TracebackType
from typing import Any

import aiohttp

from amhf.delivery.request import FuzzRequest, FuzzResponse

_LOG = logging.getLogger("amhf.delivery")

# Транспортные ошибки, на которых имеет смысл ретраиться.
_TRANSPORT_ERRORS: tuple[type[BaseException], ...] = (
    aiohttp.ClientConnectionError,
    aiohttp.ServerTimeoutError,
    asyncio.TimeoutError,
)


class _TokenBucket:
    """Ленивый асинхронный токен-бакет.

    Ёмкость == rps; токены восстанавливаются непрерывно по времени.
    Реализовано без фоновой задачи: каждый ``acquire()`` пересчитывает
    доступные токены по дельте времени и ждёт ровно сколько нужно.
    """

    def __init__(self, rate_rps: float) -> None:
        if rate_rps <= 0:
            raise ValueError("rate_limit_rps must be > 0")
        self._rate = float(rate_rps)
        self._capacity = float(rate_rps)
        self._tokens = float(rate_rps)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until 1 token is available, then consume it."""
        async with self._lock:
            while True:
                now = time.monotonic()
                # Восполняем токены по прошедшему времени.
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Сколько ждать до следующего токена.
                deficit = 1.0 - self._tokens
                wait_s = deficit / self._rate
                await asyncio.sleep(wait_s)


def _parse_charset(content_type: str | None) -> str | None:
    """Best-effort charset extractor from a ``Content-Type`` header value."""
    if not content_type:
        return None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            return part.split("=", 1)[1].strip().strip('"').strip("'") or None
    return None


def _decode_body(body: bytes, content_type: str | None) -> str:
    """Decode bytes using charset from header, then utf-8, then latin-1."""
    charset = _parse_charset(content_type)
    if charset:
        try:
            return body.decode(charset)
        except (LookupError, UnicodeDecodeError):
            _LOG.debug("charset %r failed; falling back to utf-8", charset)
    try:
        return body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return body.decode("latin-1", errors="replace")


class AsyncHTTPClient:
    """Async HTTP client used by the orchestrator to deliver fuzzed requests."""

    def __init__(
        self,
        *,
        concurrency: int,
        request_timeout_s: float,
        connect_timeout_s: float | None = None,
        rate_limit_rps: float,
        verify_ssl: bool = False,
        max_retries: int = 2,
    ) -> None:
        if concurrency <= 0:
            raise ValueError("concurrency must be > 0")
        if request_timeout_s <= 0:
            raise ValueError("request_timeout_s must be > 0")
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        self._concurrency = concurrency
        self._request_timeout_s = float(request_timeout_s)
        self._connect_timeout_s = (
            float(connect_timeout_s)
            if connect_timeout_s is not None
            else min(5.0, float(request_timeout_s))
        )
        self._verify_ssl = verify_ssl
        self._max_retries = max_retries
        self._semaphore = asyncio.Semaphore(concurrency)
        self._bucket = _TokenBucket(rate_limit_rps)
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> AsyncHTTPClient:
        timeout = aiohttp.ClientTimeout(
            total=self._request_timeout_s,
            connect=self._connect_timeout_s,
        )
        # ssl=False отключает проверку — стенд использует self-signed.
        connector = aiohttp.TCPConnector(
            ssl=bool(self._verify_ssl),
            limit=self._concurrency * 2,
        )
        jar = aiohttp.CookieJar(unsafe=False)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            cookie_jar=jar,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def send(self, req: FuzzRequest) -> FuzzResponse:
        """Send a single FuzzRequest, returning a FuzzResponse.

        Never raises: on transport failure after retries, returns a
        FuzzResponse with ``status_code=0`` and a populated ``error``.
        """
        if self._session is None:
            raise RuntimeError("AsyncHTTPClient must be used as an async context manager")
        async with self._semaphore:
            await self._bucket.acquire()
            return await self._send_with_retry(req)

    async def send_many(
        self, requests: Sequence[FuzzRequest]
    ) -> list[FuzzResponse]:
        """Send a batch of requests concurrently; preserves input order.

        Internal concurrency is throttled by ``self._semaphore`` (set in
        ``__init__``); the rate limiter applies per-request.
        """
        if not requests:
            return []
        return list(
            await asyncio.gather(*(self.send(r) for r in requests))
        )

    async def _send_with_retry(self, req: FuzzRequest) -> FuzzResponse:
        attempts = self._max_retries + 1
        last_error: str = ""
        started = time.perf_counter()
        for i in range(attempts):
            try:
                return await self._send_once(req, started_at=started)
            except _TRANSPORT_ERRORS as exc:
                last_error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
                _LOG.debug(
                    "transport error on %s %s (try %d/%d): %s",
                    req.method, req.url, i + 1, attempts, last_error,
                )
                if i + 1 >= attempts:
                    break
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return FuzzResponse(
            status_code=0,
            headers={},
            body_bytes=b"",
            body_text="",
            elapsed_ms=elapsed_ms,
            error=last_error or "transport_error",
        )

    async def _send_once(self, req: FuzzRequest, started_at: float) -> FuzzResponse:
        if self._session is None:  # pragma: no cover — guarded by send()
            raise RuntimeError("session is None")
        kwargs: dict[str, Any] = {
            "method": req.method,
            "url": req.url,
            "headers": dict(req.headers) if req.headers else None,
            "params": dict(req.query) if req.query else None,
            "allow_redirects": False,
        }
        if req.body_bytes:
            kwargs["data"] = req.body_bytes
        send_started = time.perf_counter()
        async with self._session.request(**kwargs) as resp:
            body = await resp.read()
            elapsed_ms = (time.perf_counter() - send_started) * 1000.0
            content_type = resp.headers.get("Content-Type")
            text = _decode_body(body, content_type)
            # Сохраняем фактический wall-clock с момента самого первого запуска
            # (включая failed retries) для time-based-оракула.
            total_elapsed_ms = (time.perf_counter() - started_at) * 1000.0
            # Если ретраев не было — оба значения совпадают; берём более точное.
            response_elapsed = max(elapsed_ms, total_elapsed_ms)
            return FuzzResponse(
                status_code=resp.status,
                headers=dict(resp.headers),
                body_bytes=body,
                body_text=text,
                elapsed_ms=response_elapsed,
                error=None,
            )


__all__ = ["AsyncHTTPClient"]
