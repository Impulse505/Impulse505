"""Stage 1 smoke tests — package imports, CLI version, config validates."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from amhf import __version__
from amhf.cli import cli
from amhf.config import load_config
from amhf.delivery.request import FuzzRequest, FuzzResponse
from amhf.mutators.base import (
    Layer,
    MutationSkipped,
    Registry,
    RegistryOfMutators,
)
from amhf.scheduler.chromosome import (
    MAX_CHROMOSOME_LENGTH,
    build_chromosome,
)
from amhf.storage.schema import AttemptKind, AttemptRecord
from amhf.utils.seeding import SeedManager


def test_version_constant() -> None:
    assert __version__ == "0.1.0"


def test_cli_version_command() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_list_mutators_empty_registry() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["list-mutators"])
    # Stage 1 — реестр пуст; команда должна корректно отрабатывать.
    assert result.exit_code == 0


def test_cli_validate_default_config() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli, ["validate", "-c", str(Path("configs") / "default.yaml")]
    )
    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_default_config_loads() -> None:
    cfg = load_config(Path("configs") / "default.yaml")
    assert cfg.run.total_requests == 5000
    assert cfg.run.seed == 42
    assert cfg.target.name == "dvwa-modsec"
    assert len(cfg.target.endpoints) >= 1
    assert "url_encode" in cfg.mutators.payload


def test_layer_enum_values() -> None:
    assert Layer.PAYLOAD.value == "payload"
    assert Layer.BODY.value == "body"
    assert Layer.HEADERS.value == "headers"
    assert Layer.URL.value == "url"


def test_registry_register_and_lookup() -> None:
    reg = Registry()

    class _M:
        id = "url_encode"
        layer = Layer.PAYLOAD

        def compatible_with(self, other: str) -> bool:
            del other
            return True

        def mutate(self, req, rng):  # type: ignore[no-untyped-def]
            return req

    m = _M()
    reg.register(m)  # type: ignore[arg-type]
    assert reg.by_id("url_encode") is m
    assert reg.by_layer(Layer.PAYLOAD) == [m]


def test_registry_rejects_duplicate_id() -> None:
    reg = Registry()

    class _M:
        id = "url_encode"
        layer = Layer.PAYLOAD

        def compatible_with(self, other: str) -> bool:
            del other
            return True

        def mutate(self, req, rng):  # type: ignore[no-untyped-def]
            return req

    reg.register(_M())  # type: ignore[arg-type]
    try:
        reg.register(_M())  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("Registry must reject duplicate ids")


def test_global_registry_is_registry_instance() -> None:
    assert isinstance(RegistryOfMutators, Registry)


def test_mutation_skipped_is_exception() -> None:
    assert issubclass(MutationSkipped, Exception)


def test_chromosome_validation() -> None:
    c = build_chromosome(["url_encode", "case_toggle"])
    assert c == ("url_encode", "case_toggle")
    assert len(c) == 2
    try:
        build_chromosome([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty chromosome must be rejected")
    try:
        build_chromosome(["a"] * (MAX_CHROMOSOME_LENGTH + 1))
    except ValueError:
        pass
    else:
        raise AssertionError("over-long chromosome must be rejected")


def test_fuzz_request_response_construct() -> None:
    req = FuzzRequest(method="GET", url="http://x/")
    assert req.method == "GET"
    assert req.body_bytes == b""
    resp = FuzzResponse(
        status_code=200,
        headers={},
        body_bytes=b"hi",
        body_text="hi",
        elapsed_ms=1.0,
    )
    assert resp.ok is True


def test_attempt_record_minimal() -> None:
    rec = AttemptRecord(
        run_id="run-1",
        attempt_no=0,
        target_id="dvwa-modsec",
        payload_id="sqli_taut_001",
        payload_text="' OR 1=1 --",
        chromosome=["url_encode"],
        status_code=200,
        response_time_ms=12.0,
        waf_blocked=False,
        exploit_confirmed=True,
        bypass=True,
        ucb_reward=1,
        attempt_kind=AttemptKind.MUTATION,
        seed=42,
    )
    # 18 полей фиксируются как FROZEN — проверяем поимённо.
    expected = {
        "timestamp", "run_id", "attempt_no", "target_id", "payload_id",
        "payload_text", "chromosome", "mutated_request_summary",
        "status_code", "response_time_ms", "waf_blocked",
        "waf_signature_hit", "exploit_confirmed", "oracle_reason",
        "bypass", "ucb_reward", "attempt_kind", "seed",
    }
    assert set(AttemptRecord.model_fields) == expected
    assert rec.bypass is True


def test_seed_manager_determinism() -> None:
    a = SeedManager(123)
    b = SeedManager(123)
    rng_a = a.spawn("mutators")
    rng_b = b.spawn("mutators")
    # При одинаковом master_seed и имени — одинаковая последовательность.
    assert rng_a.integers(0, 1_000_000) == rng_b.integers(0, 1_000_000)
    # Разные имена — разные последовательности.
    other = a.spawn("scheduler")
    assert other.integers(0, 1_000_000) != a.spawn("mutators").integers(0, 1_000_000)


def test_corpus_stub_files_exist_and_parse() -> None:
    import yaml

    for cls in ("sqli", "xss", "cmdi", "pathtrav"):
        with open(Path("corpus") / f"{cls}.yaml", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        assert isinstance(data, list)
        assert len(data) >= 5
        for entry in data:
            assert {"id", "class", "payload", "expected_markers"} <= set(entry)
            assert entry["class"] == cls
