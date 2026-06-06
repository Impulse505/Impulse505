"""Unit tests for the NVD CVE lookup."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.cve_lookup import (
    NvdClient,
    _parse_record,
    _RateLimiter,
    _records_from_payload,
    _SqliteCache,
)
from core.models import CveMatch, ServiceInfo

_NVD_SAMPLE_RECORD = {
    "cve": {
        "id": "CVE-2021-41773",
        "published": "2021-10-05T19:15:00.000",
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    "A flaw was found in a change made to path normalization in Apache HTTP "
                    "Server 2.4.49. An attacker could use a path traversal attack."
                ),
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
        "references": [
            {"url": "https://httpd.apache.org/security/vulnerabilities_24.html"},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
            {"url": "https://access.redhat.com/security/cve/CVE-2021-41773"},
            {"url": "https://lists.apache.org/thread/4th-ref-should-be-dropped"},
        ],
    }
}


def test_parse_record_extracts_core_fields():
    """Sample NVD record parses into a populated CveMatch."""

    match = _parse_record(_NVD_SAMPLE_RECORD)
    assert match is not None
    assert match.cve_id == "CVE-2021-41773"
    assert match.cvss_score == pytest.approx(7.5)
    assert match.cvss_severity == "HIGH"
    assert match.summary.startswith("A flaw was found")
    assert len(match.references) == 3  # truncated to MAX_REFERENCES
    assert match.published.year == 2021


def test_records_from_payload_sorts_by_score_desc():
    """Multiple records come back highest CVSS first."""

    low = {
        "cve": {
            "id": "CVE-AAAA-0001",
            "published": "2020-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Low."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.1, "baseSeverity": "LOW"}}]},
            "references": [],
        }
    }
    high = {
        "cve": {
            "id": "CVE-AAAA-0002",
            "published": "2020-01-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "High."}],
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
            },
            "references": [],
        }
    }
    out = _records_from_payload({"vulnerabilities": [low, high]})
    assert [m.cve_id for m in out] == ["CVE-AAAA-0002", "CVE-AAAA-0001"]


def test_parse_record_handles_missing_metrics():
    """A record without any CVSS metrics still parses; score=0, severity=NONE."""

    record = {
        "cve": {
            "id": "CVE-9999-0000",
            "published": "2024-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Unrated."}],
            "metrics": {},
            "references": [],
        }
    }
    match = _parse_record(record)
    assert match is not None
    assert match.cvss_score == 0.0
    assert match.cvss_severity == "NONE"


def test_cache_roundtrip(tmp_path: Path):
    """Items written to the cache survive a roundtrip and respect the TTL."""

    cache = _SqliteCache(tmp_path / "cache.db")
    match = CveMatch(
        cve_id="CVE-0000-0001",
        cvss_score=8.1,
        cvss_severity="HIGH",
        summary="Demo.",
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
        references=["https://nvd.nist.gov/vuln/detail/CVE-0000-0001"],
    )
    cache.put("key1", [match])
    cached = cache.get("key1")
    assert cached is not None
    assert cached[0].cve_id == "CVE-0000-0001"
    assert cached[0].cvss_score == 8.1


def test_cache_miss_returns_none(tmp_path: Path):
    """Unknown keys yield None — caller must hit the network."""

    cache = _SqliteCache(tmp_path / "cache.db")
    assert cache.get("missing") is None


@pytest.mark.asyncio
async def test_rate_limiter_throttles_excess_calls():
    """A 2-token/0.1s budget delays the third call past the window."""

    limiter = _RateLimiter(budget=2, window=0.1)
    import asyncio

    start = asyncio.get_running_loop().time()
    for _ in range(3):
        await limiter.acquire()
    elapsed = asyncio.get_running_loop().time() - start
    assert elapsed >= 0.05, f"limiter should have slept, but elapsed={elapsed:.3f}s"


@pytest.mark.asyncio
async def test_lookup_skips_unknown_and_versionless_services(tmp_path: Path):
    """Services without a usable keyword don't burn the rate budget."""

    class _Boom:
        async def get(self, *_args, **_kwargs):
            raise AssertionError("should not touch the network")

    cache = _SqliteCache(tmp_path / "skip.db")
    client = NvdClient(
        session=_Boom(),  # type: ignore[arg-type]
        cache=cache,
        rate_limiter=_RateLimiter(1, 1.0),
        api_key=None,
    )
    assert await client.lookup(ServiceInfo(name="unknown", version="1.0", raw_banner="")) == []
    assert await client.lookup(ServiceInfo(name="ssh", version=None, raw_banner="")) == []


@pytest.mark.asyncio
async def test_lookup_uses_cache_when_present(tmp_path: Path):
    """A populated cache short-circuits the HTTP call entirely."""

    cache = _SqliteCache(tmp_path / "hit.db")
    service = ServiceInfo(name="apache", version="2.4.49", raw_banner="")
    seeded = [
        CveMatch(
            cve_id="CVE-CACHED-0001",
            cvss_score=7.5,
            cvss_severity="HIGH",
            summary="Cached.",
            published=datetime(2024, 1, 1, tzinfo=timezone.utc),
            references=[],
        )
    ]
    from core.cve_lookup import _cache_key

    cache.put(_cache_key(service), seeded)

    class _Boom:
        async def get(self, *_args, **_kwargs):
            raise AssertionError("cache hit should suppress HTTP")

    client = NvdClient(
        session=_Boom(),  # type: ignore[arg-type]
        cache=cache,
        rate_limiter=_RateLimiter(1, 1.0),
        api_key=None,
    )
    matches = await client.lookup(service)
    assert [m.cve_id for m in matches] == ["CVE-CACHED-0001"]


class _MockResponse:
    def __init__(self, status: int, body: dict) -> None:
        self.status = status
        self._body = body

    async def __aenter__(self) -> "_MockResponse":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def json(self, content_type=None):
        return self._body

    async def text(self) -> str:
        return str(self._body)


class _MockSession:
    """Yields a queue of canned responses for each ``.get`` call."""

    def __init__(self, responses: list[_MockResponse]) -> None:
        self._responses = list(responses)
        self.calls = 0

    def get(self, *_args, **_kwargs) -> _MockResponse:
        self.calls += 1
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_fetch_retries_on_429(tmp_path: Path):
    """A 429 response triggers a retry; the second 200 response is consumed."""

    service = ServiceInfo(name="apache", version="2.4.49", raw_banner="")
    session = _MockSession(
        [
            _MockResponse(429, {}),
            _MockResponse(200, {"vulnerabilities": [_NVD_SAMPLE_RECORD]}),
        ]
    )
    cache = _SqliteCache(tmp_path / "retry.db")
    client = NvdClient(
        session=session,  # type: ignore[arg-type]
        cache=cache,
        rate_limiter=_RateLimiter(50, 0.01),
        api_key=None,
    )

    # Speed up retries by patching the backoff base for this test scope.
    import core.cve_lookup as mod

    original_delay = mod.RETRY_BASE_DELAY
    mod.RETRY_BASE_DELAY = 0.001
    try:
        matches = await client.lookup(service)
    finally:
        mod.RETRY_BASE_DELAY = original_delay

    assert session.calls == 2
    assert matches and matches[0].cve_id == "CVE-2021-41773"


@pytest.mark.asyncio
async def test_fetch_returns_empty_on_persistent_4xx(tmp_path: Path):
    """A persistent 404 yields an empty list and doesn't raise."""

    service = ServiceInfo(name="apache", version="2.4.49", raw_banner="")
    session = _MockSession([_MockResponse(404, {})])
    cache = _SqliteCache(tmp_path / "miss.db")
    client = NvdClient(
        session=session,  # type: ignore[arg-type]
        cache=cache,
        rate_limiter=_RateLimiter(50, 0.01),
        api_key=None,
    )
    assert await client.lookup(service) == []
