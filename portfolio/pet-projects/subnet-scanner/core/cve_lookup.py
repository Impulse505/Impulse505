"""NVD CVE lookup with on-disk caching and polite rate limiting.

The lookup is intentionally pragmatic: instead of building CPE strings from
service fingerprints (which requires a separate CPE dictionary), we use NVD's
``keywordSearch`` parameter with the ``"{name} {version}"`` pair. This catches the
majority of well-known issues for popular software (Apache, nginx, OpenSSH,
MySQL, vsftpd…) without the bookkeeping of a full CPE matcher. CPE-based
correlation is planned for v0.3.

Rate limits (per NVD docs):
    * No key   — 5 requests / 30s
    * With key — 50 requests / 30s

We model both with a single ``asyncio.Semaphore`` plus a token-bucket sleep,
so callers don't need to think about it. Retries on 429/503 use exponential
backoff with a small jitter.

Cache:
    SQLite file, one row per (service name, version). Payload is the parsed
    list of ``CveMatch`` serialized as JSON. Entries older than ``TTL`` are
    refetched silently.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import sqlite3
from contextlib import asynccontextmanager, closing
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncIterator

import aiohttp

from .models import CveMatch, ServiceInfo

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = timedelta(hours=24)
MAX_REFERENCES = 3
MAX_RESULTS_PER_QUERY = 20
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2.0
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)

# Rate budget (req per window) and window seconds, plus parallelism cap.
_RATE_NO_KEY = (5, 30.0)
_RATE_WITH_KEY = (50, 30.0)


def _cache_key(service: ServiceInfo) -> str:
    """Stable per-(name, version) key for the SQLite cache."""

    payload = f"{service.name.lower()}::{(service.version or '').lower()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _severity_from_score(score: float) -> str:
    """Bucket a CVSS score using the NVD-published thresholds."""

    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _pick_cvss(metrics: dict) -> tuple[float, str]:
    """Extract the highest available CVSS base score from the metrics block.

    NVD payloads occasionally ship multiple CVSS versions; we prefer v3.1,
    then v3.0, then v2.0.
    """

    for key in ("cvssMetricV31", "cvssMetricV30"):
        bucket = metrics.get(key) or []
        if bucket:
            data = bucket[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0))
            severity = data.get("baseSeverity") or _severity_from_score(score)
            return score, severity
    v2 = metrics.get("cvssMetricV2") or []
    if v2:
        data = v2[0].get("cvssData", {})
        score = float(data.get("baseScore", 0.0))
        return score, _severity_from_score(score)
    return 0.0, "NONE"


def _first_sentence(text: str) -> str:
    """Trim a description to a single sentence for terminal display."""

    text = " ".join(text.split())
    for separator in (". ", "! ", "? "):
        idx = text.find(separator)
        if idx != -1:
            return text[: idx + 1]
    return text[:240]


def _parse_record(record: dict) -> CveMatch | None:
    """Convert one NVD ``vulnerabilities[].cve`` item into a ``CveMatch``."""

    cve = record.get("cve") or record
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    summary = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            summary = _first_sentence(desc.get("value", ""))
            break

    score, severity = _pick_cvss(cve.get("metrics") or {})

    published_raw = cve.get("published") or cve.get("publishedDate") or ""
    try:
        published = datetime.fromisoformat(published_raw.replace("Z", "+00:00"))
    except ValueError:
        published = datetime.now(timezone.utc)

    references: list[str] = []
    for ref in cve.get("references", []):
        url = ref.get("url")
        if url:
            references.append(url)
        if len(references) >= MAX_REFERENCES:
            break

    return CveMatch(
        cve_id=cve_id,
        cvss_score=score,
        cvss_severity=severity,
        summary=summary,
        published=published,
        references=references,
    )


def _serialize(matches: list[CveMatch]) -> str:
    return json.dumps(
        [{**asdict(m), "published": m.published.isoformat()} for m in matches],
        ensure_ascii=False,
    )


def _deserialize(payload: str) -> list[CveMatch]:
    raw = json.loads(payload)
    out: list[CveMatch] = []
    for item in raw:
        try:
            published = datetime.fromisoformat(item["published"])
        except (KeyError, ValueError):
            published = datetime.now(timezone.utc)
        out.append(
            CveMatch(
                cve_id=item["cve_id"],
                cvss_score=float(item.get("cvss_score", 0.0)),
                cvss_severity=item.get("cvss_severity", "NONE"),
                summary=item.get("summary", ""),
                published=published,
                references=list(item.get("references", [])),
            )
        )
    return out


class _SqliteCache:
    """Thin synchronous SQLite wrapper used from worker threads."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, isolation_level=None, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nvd_cache (
                    cache_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    cached_at TEXT NOT NULL
                )
                """)

    def get(self, key: str, ttl: timedelta = CACHE_TTL) -> list[CveMatch] | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT payload, cached_at FROM nvd_cache WHERE cache_key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        payload, cached_at_raw = row
        try:
            cached_at = datetime.fromisoformat(cached_at_raw)
        except ValueError:
            return None
        if datetime.now(timezone.utc) - cached_at > ttl:
            return None
        try:
            return _deserialize(payload)
        except (json.JSONDecodeError, KeyError):
            logger.warning("cache row for %s is malformed; ignoring", key)
            return None

    def put(self, key: str, matches: list[CveMatch]) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "REPLACE INTO nvd_cache(cache_key, payload, cached_at) VALUES (?, ?, ?)",
                (key, _serialize(matches), datetime.now(timezone.utc).isoformat()),
            )


class _RateLimiter:
    """Token-bucket-ish limiter scoped to a single NVD client."""

    def __init__(self, budget: int, window: float) -> None:
        self.budget = budget
        self.window = window
        self._lock = asyncio.Lock()
        self._timestamps: list[float] = []

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            self._timestamps = [t for t in self._timestamps if now - t < self.window]
            if len(self._timestamps) >= self.budget:
                sleep_for = self.window - (now - self._timestamps[0])
                await asyncio.sleep(max(sleep_for, 0.05))
                now = loop.time()
                self._timestamps = [t for t in self._timestamps if now - t < self.window]
            self._timestamps.append(now)


class NvdClient:
    """Async NVD client with caching, retries, and rate limiting.

    Use as an async context manager::

        async with NvdClient.create(cache_path="nvd_cache.db") as client:
            matches = await client.lookup(service)
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        cache: _SqliteCache,
        rate_limiter: _RateLimiter,
        api_key: str | None,
    ) -> None:
        self._session = session
        self._cache = cache
        self._limiter = rate_limiter
        self._api_key = api_key

    @classmethod
    @asynccontextmanager
    async def create(
        cls,
        cache_path: str | Path = "nvd_cache.db",
        api_key: str | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> AsyncIterator[NvdClient]:
        key = api_key or os.environ.get("NVD_API_KEY")
        budget, window = _RATE_WITH_KEY if key else _RATE_NO_KEY
        limiter = _RateLimiter(budget=budget, window=window)
        cache = _SqliteCache(Path(cache_path))
        owns_session = session is None
        if session is None:
            session = aiohttp.ClientSession(timeout=HTTP_TIMEOUT)
        try:
            yield cls(session=session, cache=cache, rate_limiter=limiter, api_key=key)
        finally:
            if owns_session:
                await session.close()

    async def lookup(self, service: ServiceInfo) -> list[CveMatch]:
        """Return CVEs matching ``service`` from cache or NVD.

        ``unknown`` services and services without a version are skipped to
        avoid wasting the rate budget on queries with no useful keyword.
        """

        if service.name == "unknown" or not service.version:
            return []
        key = _cache_key(service)
        cached = self._cache.get(key)
        if cached is not None:
            logger.debug("cve cache hit for %s/%s", service.name, service.version)
            return cached

        matches = await self._fetch(service)
        self._cache.put(key, matches)
        return matches

    async def _fetch(self, service: ServiceInfo) -> list[CveMatch]:
        params = {
            "keywordSearch": f"{service.name} {service.version}".strip(),
            "resultsPerPage": str(MAX_RESULTS_PER_QUERY),
        }
        headers: dict[str, str] = {"User-Agent": "subnet-scanner/0.2"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        for attempt in range(MAX_RETRIES):
            await self._limiter.acquire()
            try:
                async with self._session.get(NVD_API_URL, params=params, headers=headers) as resp:
                    if resp.status in (429, 503):
                        delay = RETRY_BASE_DELAY * (2**attempt) + random.uniform(0, 0.3)
                        logger.warning(
                            "NVD %s for %s, backing off %.1fs", resp.status, params, delay
                        )
                        await asyncio.sleep(delay)
                        continue
                    if resp.status >= 400:
                        logger.warning(
                            "NVD %s for %s body=%s",
                            resp.status,
                            params,
                            (await resp.text())[:200],
                        )
                        return []
                    body = await resp.json(content_type=None)
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                delay = RETRY_BASE_DELAY * (2**attempt) + random.uniform(0, 0.3)
                logger.warning("NVD request error %s, retry in %.1fs", exc, delay)
                await asyncio.sleep(delay)
                continue

            return _records_from_payload(body)
        logger.warning("NVD lookup exhausted retries for %s", params)
        return []


def _records_from_payload(body: dict) -> list[CveMatch]:
    out: list[CveMatch] = []
    for record in body.get("vulnerabilities", []):
        parsed = _parse_record(record)
        if parsed is not None:
            out.append(parsed)
    out.sort(key=lambda m: m.cvss_score, reverse=True)
    return out


async def lookup_cves(service: ServiceInfo, client: NvdClient | None = None) -> list[CveMatch]:
    """Convenience helper that lets callers ignore client lifecycle.

    Prefer ``NvdClient.create`` when looking up many services in one batch
    so the rate limiter and cache stay shared.
    """

    if client is not None:
        return await client.lookup(service)
    async with NvdClient.create() as new_client:
        return await new_client.lookup(service)
