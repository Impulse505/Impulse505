"""Unit tests for amhf.delivery.client.AsyncHTTPClient.

Use aiohttp.test_utils.TestServer + TestClient directly to avoid pulling
in the pytest-aiohttp plugin.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer

from amhf.delivery.client import AsyncHTTPClient
from amhf.delivery.request import FuzzRequest

pytestmark = pytest.mark.asyncio


def _req(url: str, method: str = "GET") -> FuzzRequest:
    return FuzzRequest(method=method, url=url)


def _build_app() -> web.Application:
    async def ok_handler(request: web.Request) -> web.Response:
        return web.Response(text="hello", status=200)

    async def status_handler(request: web.Request) -> web.Response:
        code = int(request.match_info["code"])
        return web.Response(text=f"status {code}", status=code)

    async def slow_handler(request: web.Request) -> web.Response:
        await asyncio.sleep(0.05)
        return web.Response(text="slow", status=200)

    async def hang_handler(request: web.Request) -> web.Response:
        await asyncio.sleep(5.0)
        return web.Response(text="never", status=200)

    async def redirect_handler(request: web.Request) -> web.Response:
        return web.Response(status=302, headers={"Location": "/ok"})

    async def cp1251_handler(request: web.Request) -> web.Response:
        body = "Привет, мир".encode("cp1251")
        return web.Response(
            body=body, status=200,
            headers={"Content-Type": "text/html; charset=cp1251"},
        )

    app = web.Application()
    app.router.add_get("/ok", ok_handler)
    app.router.add_get(r"/status/{code:\d+}", status_handler)
    app.router.add_get("/slow", slow_handler)
    app.router.add_get("/hang", hang_handler)
    app.router.add_get("/redirect", redirect_handler)
    app.router.add_get("/cp1251", cp1251_handler)
    return app


@pytest_asyncio.fixture()
async def server() -> AsyncIterator[TestServer]:
    srv = TestServer(_build_app())
    await srv.start_server()
    try:
        yield srv
    finally:
        await srv.close()


def _url(server: TestServer, path: str) -> str:
    return str(server.make_url(path))


# --------------------------- tests ---------------------------


async def test_successful_200(server: TestServer) -> None:
    async with AsyncHTTPClient(
        concurrency=2, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(_req(_url(server, "/ok")))
    assert resp.status_code == 200
    assert resp.body_text == "hello"
    assert resp.error is None
    assert resp.elapsed_ms >= 0.0


async def test_non_2xx_no_retry(server: TestServer) -> None:
    async with AsyncHTTPClient(
        concurrency=2, request_timeout_s=2.0, rate_limit_rps=100.0, max_retries=3,
    ) as client:
        resp = await client.send(_req(_url(server, "/status/500")))
    assert resp.status_code == 500
    assert resp.error is None


async def test_timeout_returns_error_response(server: TestServer) -> None:
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=0.2, rate_limit_rps=100.0, max_retries=0,
    ) as client:
        resp = await client.send(_req(_url(server, "/hang")))
    assert resp.status_code == 0
    assert resp.error is not None
    assert resp.body_bytes == b""


async def test_transport_error_retried_until_exhausted() -> None:
    bad_url = "http://127.0.0.1:1/never"
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=0.5, rate_limit_rps=100.0, max_retries=2,
    ) as client:
        resp = await client.send(_req(bad_url))
    assert resp.status_code == 0
    assert resp.error is not None


async def test_no_follow_redirects(server: TestServer) -> None:
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(_req(_url(server, "/redirect")))
    assert resp.status_code == 302
    assert "Location" in resp.headers


async def test_concurrency_speedup(server: TestServer) -> None:
    url = _url(server, "/slow")
    async with AsyncHTTPClient(
        concurrency=20, request_timeout_s=5.0, rate_limit_rps=10_000.0,
    ) as client:
        started = time.perf_counter()
        results = await asyncio.gather(*(client.send(_req(url)) for _ in range(100)))
        elapsed = time.perf_counter() - started
    assert all(r.status_code == 200 for r in results)
    # 100 requests at concurrency=20 with 50 ms each => ~5 batches * 50 ms.
    assert elapsed < 1.5, f"actual elapsed {elapsed:.3f}s"


async def test_rate_limit_enforced(server: TestServer) -> None:
    url = _url(server, "/ok")
    async with AsyncHTTPClient(
        concurrency=10, request_timeout_s=5.0, rate_limit_rps=10.0,
    ) as client:
        started = time.perf_counter()
        await asyncio.gather(*(client.send(_req(url)) for _ in range(30)))
        elapsed = time.perf_counter() - started
    assert elapsed >= 2.0, f"rate limit not enforced: elapsed {elapsed:.3f}s"


async def test_body_decoding_charset_cp1251(server: TestServer) -> None:
    async with AsyncHTTPClient(
        concurrency=1, request_timeout_s=2.0, rate_limit_rps=100.0,
    ) as client:
        resp = await client.send(_req(_url(server, "/cp1251")))
    assert resp.status_code == 200
    assert "Привет, мир" in resp.body_text


async def test_send_outside_context_manager_raises() -> None:
    client = AsyncHTTPClient(
        concurrency=1, request_timeout_s=1.0, rate_limit_rps=10.0,
    )
    with pytest.raises(RuntimeError):
        await client.send(_req("http://127.0.0.1:1/x"))


async def test_invalid_args() -> None:
    with pytest.raises(ValueError):
        AsyncHTTPClient(concurrency=0, request_timeout_s=1.0, rate_limit_rps=1.0)
    with pytest.raises(ValueError):
        AsyncHTTPClient(concurrency=1, request_timeout_s=0.0, rate_limit_rps=1.0)
    with pytest.raises(ValueError):
        AsyncHTTPClient(concurrency=1, request_timeout_s=1.0, rate_limit_rps=0.0)
    with pytest.raises(ValueError):
        AsyncHTTPClient(
            concurrency=1, request_timeout_s=1.0, rate_limit_rps=1.0, max_retries=-1,
        )
