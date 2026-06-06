"""Unit tests for the scan orchestrator pipeline.

The orchestrator's job is to glue discovery, port scan, fingerprinting and
CVE lookup together. These tests stub each stage at the orchestrator module
boundary so the wiring (and its error isolation) is exercised without any
real network.
"""

from __future__ import annotations

import io
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import pytest
from rich.console import Console
from rich.progress import Progress

from core import orchestrator
from core.models import CveMatch, Host, OpenPort, ScanConfig, ServiceInfo


def _host(ip: str = "10.0.0.1") -> Host:
    return Host(ip=ip, alive=True, discovered_at=datetime.now(timezone.utc))


def _cve() -> CveMatch:
    return CveMatch(
        cve_id="CVE-2021-41773",
        cvss_score=7.5,
        cvss_severity="HIGH",
        summary="x",
        published=datetime(2021, 10, 5, tzinfo=timezone.utc),
        references=[],
    )


class _FakeClient:
    def __init__(self, cves: list[CveMatch]) -> None:
        self._cves = cves
        self.calls = 0

    async def lookup(self, service: ServiceInfo) -> list[CveMatch]:
        self.calls += 1
        return list(self._cves)


def _setup(
    monkeypatch,
    *,
    hosts: list[Host],
    open_ports: list[OpenPort],
    service: ServiceInfo | Exception | None,
    cves: list[CveMatch],
) -> _FakeClient:
    """Patch every pipeline stage and return the fake CVE client."""

    async def fake_discover(targets, **kwargs):
        callback = kwargs.get("on_probe")
        if callback is not None:
            for ip in targets:
                callback(ip, True)
        return list(hosts)

    async def fake_scan_ports(host, ports, semaphore, timeout, delay=0.0):
        return list(open_ports)

    async def fake_fingerprint(host, port, timeout=2.0):
        if isinstance(service, Exception):
            raise service
        return service

    client = _FakeClient(cves)

    @asynccontextmanager
    async def fake_create(**kwargs):
        yield client

    class _FakeNvd:
        create = staticmethod(fake_create)

    monkeypatch.setattr(orchestrator, "discover_hosts", fake_discover)
    monkeypatch.setattr(orchestrator, "scan_ports", fake_scan_ports)
    monkeypatch.setattr(orchestrator, "fingerprint", fake_fingerprint)
    monkeypatch.setattr(orchestrator, "NvdClient", _FakeNvd)
    return client


@pytest.mark.asyncio
async def test_full_pipeline_enriches_ports_with_cves(monkeypatch):
    client = _setup(
        monkeypatch,
        hosts=[_host()],
        open_ports=[OpenPort(port=80)],
        service=ServiceInfo("apache", "2.4.49", "banner"),
        cves=[_cve()],
    )
    result = await orchestrator.run_scan(ScanConfig(targets=["10.0.0.1"], ports=[80]))

    assert len(result.hosts) == 1
    port, service, cves = result.hosts[0].open_ports[0]
    assert port.port == 80
    assert service is not None and service.name == "apache"
    assert [c.cve_id for c in cves] == ["CVE-2021-41773"]
    assert client.calls == 1


@pytest.mark.asyncio
async def test_no_alive_hosts_short_circuits(monkeypatch):
    client = _setup(
        monkeypatch,
        hosts=[],
        open_ports=[OpenPort(port=80)],
        service=ServiceInfo("apache", "2.4.49", "banner"),
        cves=[_cve()],
    )
    result = await orchestrator.run_scan(ScanConfig(targets=["10.0.0.1"], ports=[80]))
    assert result.hosts == []
    assert client.calls == 0


@pytest.mark.asyncio
async def test_skip_banner_leaves_service_none_and_skips_fingerprint(monkeypatch):
    # A fingerprint that would explode if called proves it is never invoked.
    client = _setup(
        monkeypatch,
        hosts=[_host()],
        open_ports=[OpenPort(port=80)],
        service=RuntimeError("fingerprint must not run when skip_banner=True"),
        cves=[_cve()],
    )
    config = ScanConfig(targets=["10.0.0.1"], ports=[80], skip_banner=True, enable_cve=False)
    result = await orchestrator.run_scan(config)
    port, service, cves = result.hosts[0].open_ports[0]
    assert service is None
    assert cves == []
    assert client.calls == 0


@pytest.mark.asyncio
async def test_cve_disabled_yields_empty_cve_lists(monkeypatch):
    client = _setup(
        monkeypatch,
        hosts=[_host()],
        open_ports=[OpenPort(port=80)],
        service=ServiceInfo("apache", "2.4.49", "banner"),
        cves=[_cve()],
    )
    config = ScanConfig(targets=["10.0.0.1"], ports=[80], enable_cve=False)
    result = await orchestrator.run_scan(config)
    _, service, cves = result.hosts[0].open_ports[0]
    assert service is not None
    assert cves == []
    assert client.calls == 0


@pytest.mark.asyncio
async def test_fingerprint_exception_is_isolated(monkeypatch):
    _setup(
        monkeypatch,
        hosts=[_host()],
        open_ports=[OpenPort(port=80)],
        service=RuntimeError("banner grab blew up"),
        cves=[_cve()],
    )
    result = await orchestrator.run_scan(ScanConfig(targets=["10.0.0.1"], ports=[80]))
    port, service, cves = result.hosts[0].open_ports[0]
    assert service is None  # crash swallowed, port still reported
    assert cves == []


@pytest.mark.asyncio
async def test_run_scan_drives_progress(monkeypatch):
    _setup(
        monkeypatch,
        hosts=[_host("10.0.0.1"), _host("10.0.0.2")],
        open_ports=[OpenPort(port=80)],
        service=ServiceInfo("apache", "2.4.49", "banner"),
        cves=[_cve()],
    )
    config = ScanConfig(targets=["10.0.0.1", "10.0.0.2"], ports=[80])
    console = Console(file=io.StringIO(), force_terminal=False)
    with Progress(console=console) as progress:
        result = await orchestrator.run_scan(config, progress=progress)
    assert len(result.hosts) == 2
