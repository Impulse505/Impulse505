"""Главный цикл AMHF.

Класс :class:`Orchestrator` соединяет четыре подсистемы — мутаторы,
адаптивный планировщик (UCB1+GA), оракул и хранилище — в один async-loop
с поддержкой resume и метрик.
"""

from __future__ import annotations

import contextlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from amhf.config import Config, EndpointConfig
from amhf.corpus import Corpus, CorpusEntry
from amhf.delivery.client import AsyncHTTPClient
from amhf.delivery.request import FuzzRequest, FuzzResponse
from amhf.mutators.base import (
    Layer,
    MutationSkipped,
    RegistryOfMutators,
)
from amhf.oracle import (
    CombinedOracle,
    OracleReason,
    OracleVerdict,
    TimingOracle,
)
from amhf.scheduler import AdaptiveScheduler, Chromosome
from amhf.storage import (
    AttemptKind,
    AttemptRecord,
    CSVSink,
    JSONLSink,
    Sink,
    SQLiteSink,
    StorageError,
)
from amhf.utils.seeding import SeedManager

_LOG = logging.getLogger("amhf.orchestrator")

# Канонический порядок применения слоёв в хромосоме.
_LAYER_ORDER: tuple[Layer, ...] = tuple(Layer)


# --------------------------------------------------------------------------- #
# Lightweight progress tracker (logging-only by default)                       #
# --------------------------------------------------------------------------- #


class _ProgressTracker:
    """Минимальный progress-tracker: счётчики + опц. rich.Progress."""

    def __init__(self, total: int, *, console_enabled: bool = False) -> None:
        self.total = max(0, total)
        self.attempts = 0
        self.bypasses = 0
        self.blocks = 0
        self.skips = 0
        self.transport_errors = 0
        self.server_errors = 0
        self._console_enabled = console_enabled

    def update(self, verdict: OracleVerdict) -> None:
        self.attempts += 1
        if verdict.bypass:
            self.bypasses += 1
        if verdict.waf_blocked:
            self.blocks += 1
        if verdict.reason == OracleReason.SERVER_ERROR:
            self.server_errors += 1
        if verdict.reason == OracleReason.TRANSPORT_ERROR:
            self.transport_errors += 1
        # Логируем через каждые 50 попыток, не чаще — иначе зашумит.
        if self.attempts % 50 == 0 or self.attempts == self.total:
            _LOG.info(
                "progress: %d/%d attempts (%d bypass, %d block)",
                self.attempts, self.total, self.bypasses, self.blocks,
            )

    def update_skip(self) -> None:
        self.attempts += 1
        self.skips += 1


# --------------------------------------------------------------------------- #
# Public dataclasses / models                                                 #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class OrchestratorDeps:
    """Контейнер всех зависимостей оркестратора (DI-стиль)."""

    cfg: Config
    corpus: Corpus
    client: AsyncHTTPClient
    scheduler: AdaptiveScheduler
    oracle: CombinedOracle
    timing: TimingOracle
    sinks: list[Sink]
    seed_manager: SeedManager
    run_id: str
    output_dir: Path
    progress: _ProgressTracker | None = field(default=None)


class RunSummary(BaseModel):
    """Итоговое сводное описание одного запуска."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    started_at: datetime
    finished_at: datetime
    total_attempts: int
    bypasses: int
    bypass_rate: float
    blocks: int
    server_errors: int
    transport_errors: int
    pool_size_initial: int
    pool_size_final: int
    seed: int
    elapsed_seconds: float


# --------------------------------------------------------------------------- #
# Orchestrator                                                                 #
# --------------------------------------------------------------------------- #


class Orchestrator:
    """Главный async-цикл AMHF (см. :mod:`amhf.orchestrator`)."""

    def __init__(self, deps: OrchestratorDeps) -> None:
        self.deps = deps
        # Поддержка resume: смещение начального attempt_no.
        self._restored_attempt_no: int = 0
        self._initial_pool_size: int = deps.scheduler.pool_size

    # ------------------------------------------------------------------ #
    # Bootstrap (factory)                                                #
    # ------------------------------------------------------------------ #
    @classmethod
    async def from_config(
        cls,
        cfg: Config,
        *,
        run_id: str | None = None,
    ) -> Orchestrator:
        """Сконструировать оркестратор по Config: open all dependencies."""
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
        rid = run_id or f"run-{timestamp}"
        output_dir = Path(_subst_timestamp(cfg.storage.output_dir, timestamp))
        output_dir.mkdir(parents=True, exist_ok=True)

        seed_mgr = SeedManager(master_seed=cfg.run.seed)
        sched_rng = seed_mgr.spawn("scheduler")
        # Загружаем corpus.
        corpus = Corpus.from_yaml_paths(
            cfg.corpus.paths,
            filter_class=cfg.corpus.filter_class,
            max_payloads=cfg.corpus.max_payloads,
        )

        # Собираем алфавит мутаторов из конфига.
        alphabet = list(_alphabet_from_config(cfg))
        scheduler = AdaptiveScheduler(
            cfg.scheduler, mutator_ids=alphabet, rng=sched_rng,  # type: ignore[arg-type]
        )

        # Открываем HTTP-клиент.
        client = AsyncHTTPClient(
            concurrency=cfg.run.concurrency,
            request_timeout_s=cfg.run.request_timeout_s,
            rate_limit_rps=cfg.run.rate_limit_rps,
        )
        await client.__aenter__()

        # Timing initially — fixed-threshold; будет перезаписан calibrate_timing.
        timing = TimingOracle.from_threshold(
            cfg.oracle.backend.sqli.time_delay_threshold_ms
        )
        oracle = CombinedOracle(cfg.oracle, timing=timing)

        # Sinks — открываем по списку формата. При любой ошибке закрываем
        # уже открытые ресурсы, чтобы не утекли файлы / aiohttp-сессии.
        sinks: list[Sink] = []
        try:
            for fmt in cfg.storage.formats:
                sink = _build_sink(fmt, output_dir, cfg.storage.flush_every)
                sink.open(rid)
                sinks.append(sink)
            deps = OrchestratorDeps(
                cfg=cfg,
                corpus=corpus,
                client=client,
                scheduler=scheduler,
                oracle=oracle,
                timing=timing,
                sinks=sinks,
                seed_manager=seed_mgr,
                run_id=rid,
                output_dir=output_dir,
                progress=_ProgressTracker(total=cfg.run.total_requests),
            )
            orch = cls(deps)
            # Если в конфиге задан resume_from — пробуем подцепить состояние.
            if cfg.run.resume_from:
                orch._restore(cfg.run.resume_from)
        except BaseException:
            for sink in sinks:
                with contextlib.suppress(Exception):
                    sink.close()
            with contextlib.suppress(Exception):
                await client.__aexit__(None, None, None)
            raise
        return orch

    # ------------------------------------------------------------------ #
    # Calibration                                                         #
    # ------------------------------------------------------------------ #
    async def calibrate_timing(self, samples: int = 20) -> None:
        """Откалибровать TimingOracle по baseline-выборке latency."""
        cfg = self.deps.cfg
        endpoint = cfg.target.endpoints[0]
        url = _full_url(cfg.target.base_url, endpoint)
        latencies: list[float] = []
        for _ in range(samples):
            req = FuzzRequest(
                method=endpoint.method,
                url=url,
                headers={"User-Agent": "amhf/baseline"},
                query=dict(endpoint.params),
                attack_class=endpoint.attack_class,
            )
            resp = await self.deps.client.send(req)
            if resp.error is None and resp.status_code != 0:
                latencies.append(resp.elapsed_ms)
        min_n = cfg.oracle.backend.timing_baseline_min_samples
        if len(latencies) >= min_n and _has_variance(latencies):
            new_timing = TimingOracle.calibrated(
                latencies,
                k=cfg.oracle.backend.timing_k,
                min_samples=min_n,
            )
        else:
            new_timing = TimingOracle.from_threshold(
                cfg.oracle.backend.sqli.time_delay_threshold_ms
            )
        self.deps.timing = new_timing
        # Пробрасываем новый timing в backend-оракул через приватный атрибут;
        # BackendOracle публичного сеттера для timing не имеет.
        self.deps.oracle.backend.set_timing(new_timing)
        _LOG.info(
            "TimingOracle calibrated: threshold=%.1f ms (n=%d)",
            new_timing.threshold_ms, len(latencies),
        )

    # Main loop: батч-выбор хромосом → мутация → доставка → оракул → reward
    async def run_main_loop(self) -> RunSummary:
        """Главный цикл AMHF: батч-выбор хромосом → мутация → доставка
        → оракул → запись → reward.
        """
        # 1) Калибровка TimingOracle (если фикс-порог не был перезаписан).
        if self.deps.timing.fixed_threshold_ms is not None and self._restored_attempt_no == 0:
            await self.calibrate_timing()
        cfg = self.deps.cfg
        started = datetime.now(tz=UTC)
        attempt_no = self._restored_attempt_no  # 0 при чистом старте
        progress = self.deps.progress
        total = cfg.run.total_requests
        while attempt_no < total:
            # 2) Берём батч хромосом и payload'ов.
            batch_size = min(cfg.run.concurrency, total - attempt_no)
            chromosomes = self.deps.scheduler.next_batch(batch_size)
            # Если пул меньше batch_size — циклически добиваем до batch_size,
            # чтобы pool=1 (S1 baseline) всё равно мог использовать concurrency.
            if 0 < len(chromosomes) < batch_size:
                chromosomes = [
                    chromosomes[i % len(chromosomes)] for i in range(batch_size)
                ]
            rng = self.deps.seed_manager.fresh(f"step-{attempt_no}")
            payloads = [self.deps.corpus.sample(rng) for _ in range(batch_size)]
            endpoints = [self._pick_endpoint(p.cls) for p in payloads]
            # 3) Применяем мутации; MutationSkipped — пропуск.
            triples: list[tuple[Chromosome, CorpusEntry, FuzzRequest | None]] = []
            for chrom, entry, ep in zip(
                chromosomes, payloads, endpoints, strict=True
            ):
                base_req = self._build_request(ep, entry)
                try:
                    mutated: FuzzRequest | None = self._apply_chromosome(
                        chrom, base_req, rng
                    )
                except MutationSkipped:
                    mutated = None
                triples.append((chrom, entry, mutated))
            # 4) Параллельная доставка реальных запросов.
            sendable = [(c, e, r) for c, e, r in triples if r is not None]
            responses = await self.deps.client.send_many(
                [r for _, _, r in sendable]
            )
            # 5) Оракул и запись.
            results: list[tuple[Chromosome, int]] = []
            for (chrom, entry, req), resp in zip(
                sendable, responses, strict=True
            ):
                verdict = self.deps.oracle.evaluate(
                    resp,
                    entry.cls,
                    payload_text=entry.payload,
                    expected_markers=tuple(entry.expected_markers),
                )
                rec = self._make_record(
                    attempt_no, chrom, entry, req, resp, verdict
                )
                self._write_record(rec)
                results.append((chrom, 1 if verdict.bypass else 0))
                attempt_no += 1
                if progress is not None:
                    progress.update(verdict)
            # 6) MutationSkipped — записываем skip-record c bypass=False.
            for chrom, entry, _ in (t for t in triples if t[2] is None):
                self._record_skip(attempt_no, chrom, entry)
                results.append((chrom, 0))
                attempt_no += 1
                if progress is not None:
                    progress.update_skip()
            # 7) Reward пакетом — adaptive.report_rewards триггерит GA.
            self.deps.scheduler.report_rewards(results)
        return self._finalize(started, attempt_no)

    # ------------------------------------------------------------------ #
    # Finalisation                                                        #
    # ------------------------------------------------------------------ #
    async def aclose(self) -> None:
        """Сбросить и закрыть все ресурсы; записать summary/state."""
        # Persist scheduler state for resume.
        try:
            state = self.deps.scheduler.export_state()
            state["run_id"] = self.deps.run_id
            state["next_attempt_no"] = self._restored_attempt_no
            state_path = self.deps.output_dir / "scheduler_state.json"
            state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except Exception:  # pragma: no cover — резерв на случай permissions
            _LOG.exception("failed to persist scheduler state")
        for sink in self.deps.sinks:
            try:
                sink.close()
            except StorageError:
                _LOG.exception("sink.close() failed")
        try:
            await self.deps.client.__aexit__(None, None, None)
        except Exception:  # pragma: no cover
            _LOG.exception("client.aexit failed")

    # ------------------------------------------------------------------ #
    # Helpers — keep run_main_loop short                                 #
    # ------------------------------------------------------------------ #
    def _pick_endpoint(self, attack_class: str) -> EndpointConfig:
        """Pick the first endpoint matching attack_class, fallback to first."""
        for ep in self.deps.cfg.target.endpoints:
            if ep.attack_class == attack_class:
                return ep
        return self.deps.cfg.target.endpoints[0]

    def _build_request(
        self, endpoint: EndpointConfig, entry: CorpusEntry
    ) -> FuzzRequest:
        """Construct a fresh FuzzRequest for one payload+endpoint pair."""
        url = _full_url(self.deps.cfg.target.base_url, endpoint)
        query = dict(endpoint.params)
        # Подставляем raw payload в фаззинговый параметр (мутаторы будут
        # дальше его трансформировать).
        query[endpoint.param_to_fuzz] = entry.payload
        headers: dict[str, str] = {"User-Agent": "amhf/0.1.0"}
        if endpoint.session_cookie:
            headers["Cookie"] = endpoint.session_cookie
        return FuzzRequest(
            method=endpoint.method,
            url=url,
            headers=headers,
            query=query,
            body_bytes=(endpoint.body_template or "").encode("utf-8"),
            attack_class=endpoint.attack_class,
            payload_id=entry.id,
            payload_text=entry.payload,
            param_to_fuzz=endpoint.param_to_fuzz,
        )

    def _apply_chromosome(
        self,
        chrom: Chromosome,
        req: FuzzRequest,
        rng: Any,
    ) -> FuzzRequest:
        """Применить гены хромосомы в каноническом порядке слоёв."""
        if not chrom:
            return req
        # Сортируем по индексу слоя в Layer enum.
        layer_index = {ly: i for i, ly in enumerate(_LAYER_ORDER)}
        ordered = sorted(
            chrom,
            key=lambda gid: layer_index.get(
                _safe_layer(gid), len(_LAYER_ORDER)
            ),
        )
        for gene in ordered:
            try:
                m = RegistryOfMutators.by_id(gene)
            except KeyError:
                continue  # неизвестный id — пропускаем
            req = m.mutate(req, rng)
        return req

    def _make_record(
        self,
        attempt_no: int,
        chrom: Chromosome,
        entry: CorpusEntry,
        req: FuzzRequest,
        resp: FuzzResponse,
        verdict: OracleVerdict,
    ) -> AttemptRecord:
        return AttemptRecord(
            run_id=self.deps.run_id,
            attempt_no=attempt_no,
            target_id=self.deps.cfg.target.name,
            payload_id=entry.id,
            payload_text=entry.payload,
            chromosome=list(chrom),
            mutated_request_summary=f"{req.method} {req.url}",
            status_code=resp.status_code,
            response_time_ms=resp.elapsed_ms,
            waf_blocked=verdict.waf_blocked,
            waf_signature_hit=verdict.waf_signature_hit,
            exploit_confirmed=verdict.exploit_confirmed,
            oracle_reason=verdict.reason.value,
            bypass=verdict.bypass,
            ucb_reward=1 if verdict.bypass else 0,
            attempt_kind=AttemptKind.MUTATION,
            seed=self.deps.cfg.run.seed,
        )

    def _record_skip(
        self, attempt_no: int, chrom: Chromosome, entry: CorpusEntry
    ) -> None:
        rec = AttemptRecord(
            run_id=self.deps.run_id,
            attempt_no=attempt_no,
            target_id=self.deps.cfg.target.name,
            payload_id=entry.id,
            payload_text=entry.payload,
            chromosome=list(chrom),
            mutated_request_summary="SKIP (MutationSkipped)",
            status_code=0,
            response_time_ms=0.0,
            waf_blocked=False,
            waf_signature_hit=None,
            exploit_confirmed=False,
            oracle_reason="mutation_skipped",
            bypass=False,
            ucb_reward=0,
            attempt_kind=AttemptKind.MUTATION,
            seed=self.deps.cfg.run.seed,
        )
        self._write_record(rec)

    def _write_record(self, record: AttemptRecord) -> None:
        for sink in self.deps.sinks:
            try:
                sink.write(record)
            except StorageError:
                _LOG.exception("sink.write failed for %s", type(sink).__name__)

    def _finalize(self, started: datetime, attempt_no: int) -> RunSummary:
        finished = datetime.now(tz=UTC)
        progress = self.deps.progress
        bypasses = progress.bypasses if progress is not None else 0
        blocks = progress.blocks if progress is not None else 0
        srv_err = progress.server_errors if progress is not None else 0
        transport_err = progress.transport_errors if progress is not None else 0
        elapsed = (finished - started).total_seconds()
        rate = bypasses / attempt_no if attempt_no > 0 else 0.0
        summary = RunSummary(
            run_id=self.deps.run_id,
            started_at=started,
            finished_at=finished,
            total_attempts=attempt_no,
            bypasses=bypasses,
            bypass_rate=rate,
            blocks=blocks,
            server_errors=srv_err,
            transport_errors=transport_err,
            pool_size_initial=self._initial_pool_size,
            pool_size_final=self.deps.scheduler.pool_size,
            seed=self.deps.cfg.run.seed,
            elapsed_seconds=elapsed,
        )
        # Пишем summary.json в output_dir.
        try:
            (self.deps.output_dir / "summary.json").write_text(
                summary.model_dump_json(indent=2), encoding="utf-8"
            )
        except OSError:  # pragma: no cover
            _LOG.exception("failed to write summary.json")
        return summary

    def _restore(self, resume_from: str) -> None:
        """Загрузить scheduler-state по пути resume_from (рядом с output_dir)."""
        candidate = Path(resume_from)
        if not candidate.is_absolute():
            # Ищем рядом с output_dir/.. (т.е. под results/).
            candidate = self.deps.output_dir.parent / resume_from
        state_path = candidate / "scheduler_state.json"
        if not state_path.exists():
            raise StorageError(
                f"resume_from={resume_from!r}: no scheduler_state.json at {state_path}"
            )
        state: dict[str, Any] = json.loads(
            state_path.read_text(encoding="utf-8")
        )
        existing_run_id = state.get("run_id")
        if existing_run_id and existing_run_id != self.deps.run_id:
            raise StorageError(
                f"resume run_id mismatch: state={existing_run_id!r} != "
                f"current={self.deps.run_id!r}"
            )
        self.deps.scheduler.import_state(state)
        self._restored_attempt_no = int(state.get("next_attempt_no", 0))
        _LOG.info(
            "resume: restored at attempt_no=%d, pool_size=%d",
            self._restored_attempt_no, self.deps.scheduler.pool_size,
        )


# --------------------------------------------------------------------------- #
# Module-level helpers                                                         #
# --------------------------------------------------------------------------- #


def _alphabet_from_config(cfg: Config) -> list[str]:
    """Concatenate all four mutator lists, preserving config order."""
    out: list[str] = []
    out.extend(cfg.mutators.payload)
    out.extend(cfg.mutators.body)
    out.extend(cfg.mutators.headers)
    out.extend(cfg.mutators.url)
    return out


def _build_sink(fmt: str, output_dir: Path, flush_every: int) -> Sink:
    if fmt == "csv":
        return CSVSink(output_dir, flush_every=flush_every)
    if fmt == "sqlite":
        return SQLiteSink(output_dir, flush_every=flush_every)
    if fmt == "jsonl":
        return JSONLSink(output_dir, flush_every=flush_every)
    raise ValueError(f"unknown sink format: {fmt!r}")


def _full_url(base: str, endpoint: EndpointConfig) -> str:
    base_clean = base.rstrip("/")
    path = endpoint.path if endpoint.path.startswith("/") else "/" + endpoint.path
    return base_clean + path


def _subst_timestamp(template: str, timestamp: str) -> str:
    return template.replace("{timestamp}", timestamp)


def _has_variance(samples: list[float]) -> bool:
    if len(samples) < 2:
        return False
    mn, mx = min(samples), max(samples)
    return (mx - mn) > 1e-6


def _safe_layer(gene: str) -> Layer:
    """Return Layer of gene; fallback to URL (last) if unknown."""
    try:
        return RegistryOfMutators.by_id(gene).layer
    except KeyError:
        return Layer.URL


__all__ = [
    "Orchestrator",
    "OrchestratorDeps",
    "RunSummary",
]
