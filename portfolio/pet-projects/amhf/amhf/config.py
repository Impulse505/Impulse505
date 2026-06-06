"""Pydantic v2 schema for AMHF YAML configuration (FROZEN).

Структура зеркалит configs/default.yaml. Все секции обязательные кроме
помеченных Optional. Расширение схемы без RFC запрещено.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Strict(BaseModel):
    """Common base — запрещаем неизвестные ключи, чтобы опечатки в YAML падали сразу."""

    model_config = ConfigDict(extra="forbid", frozen=True)


# ---------- run ----------

class RunConfig(_Strict):
    total_requests: int = Field(gt=0)
    concurrency: int = Field(gt=0)
    request_timeout_s: float = Field(gt=0.0)
    rate_limit_rps: float = Field(gt=0.0)
    seed: int
    resume_from: str | None = None


# ---------- target ----------

class EndpointConfig(_Strict):
    path: str
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    params: dict[str, str] = Field(default_factory=dict)
    attack_class: Literal["sqli", "xss", "cmdi", "pathtrav"]
    param_to_fuzz: str
    session_cookie: str | None = None
    body_template: str | None = None


class TargetConfig(_Strict):
    name: str
    base_url: str
    endpoints: list[EndpointConfig] = Field(min_length=1)


# ---------- corpus ----------

class CorpusConfig(_Strict):
    paths: list[Path] = Field(min_length=1)
    filter_class: Literal["sqli", "xss", "cmdi", "pathtrav"] | None = None
    max_payloads: int | None = None


# ---------- scheduler ----------

class GAConfig(_Strict):
    period: int = Field(gt=0)
    top_k: int = Field(gt=0)
    offspring_per_round: int = Field(gt=0)
    p_replace: float = Field(ge=0.0, le=1.0)
    p_insert: float = Field(ge=0.0, le=1.0)
    p_delete: float = Field(ge=0.0, le=1.0)
    min_plays_for_selection: int = Field(ge=0)


class SchedulerConfig(_Strict):
    type: Literal["ucb_with_ga", "ucb1_only", "uniform"]
    initial_pool_size: int = Field(gt=0)
    max_chromosome_length: int = Field(gt=0, le=5)
    ucb_c: float = Field(gt=0.0)
    ga: GAConfig


# ---------- mutators ----------

class MutatorsConfig(_Strict):
    payload: list[str] = Field(default_factory=list)
    body: list[str] = Field(default_factory=list)
    headers: list[str] = Field(default_factory=list)
    url: list[str] = Field(default_factory=list)


# ---------- oracle ----------

class WafOracleConfig(_Strict):
    blocked_codes: list[int] = Field(default_factory=list)
    blocked_body_signatures: list[str] = Field(default_factory=list)
    # Soft body-size hint: ModSecurity may return 200 with a small block page.
    block_page_size_max: int = Field(default=4096, gt=0)


class SqliOracleConfig(_Strict):
    error_signatures: list[str] = Field(default_factory=list)
    flag_marker: str = "AMHF_FLAG_"
    time_delay_threshold_ms: float = Field(default=2500.0, gt=0.0)


class XssOracleConfig(_Strict):
    reflection_check: bool = True


class CmdiOracleConfig(_Strict):
    command_marker: str = "amhf_cmd_marker"


class PathTravOracleConfig(_Strict):
    canary_marker: str = "amhf_canary_v1"


class BackendOracleConfig(_Strict):
    sqli: SqliOracleConfig = Field(default_factory=SqliOracleConfig)
    xss: XssOracleConfig = Field(default_factory=XssOracleConfig)
    cmdi: CmdiOracleConfig = Field(default_factory=CmdiOracleConfig)
    pathtrav: PathTravOracleConfig = Field(default_factory=PathTravOracleConfig)
    # TimingOracle parameters (used by SQLi blind-time detection).
    timing_k: float = Field(default=3.0, gt=0.0)
    timing_baseline_min_samples: int = Field(default=20, ge=5)


class OracleConfig(_Strict):
    waf: WafOracleConfig
    backend: BackendOracleConfig = Field(default_factory=BackendOracleConfig)


# ---------- storage ----------

SinkFormat = Literal["csv", "sqlite", "jsonl"]


class StorageConfig(_Strict):
    output_dir: str
    formats: list[SinkFormat] = Field(min_length=1)
    flush_every: int = Field(gt=0)


# ---------- logging ----------

class LoggingConfig(_Strict):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    json_file: str | None = None
    human_console: bool = True


# ---------- root ----------

class Config(_Strict):
    """Root config object — корневой объект YAML."""

    run: RunConfig
    target: TargetConfig
    corpus: CorpusConfig
    scheduler: SchedulerConfig
    mutators: MutatorsConfig
    oracle: OracleConfig
    storage: StorageConfig
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("mutators")
    @classmethod
    def _at_least_one_mutator(cls, value: MutatorsConfig) -> MutatorsConfig:
        total = (
            len(value.payload)
            + len(value.body)
            + len(value.headers)
            + len(value.url)
        )
        if total == 0:
            raise ValueError("mutators: at least one mutator must be enabled")
        return value


def load_config(path: Path | str) -> Config:
    """Load and validate a YAML config from disk."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"Config root must be a mapping, got {type(raw).__name__}")
    return Config.model_validate(raw)
