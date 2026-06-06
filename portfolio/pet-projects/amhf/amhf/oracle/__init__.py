"""AMHF Oracle subsystem — WAF + Backend + Timing + Combined.

Public API:
    * :class:`WafOracle` — детектор WAF-блока.
    * :class:`BackendOracle` — подтверждение эксплуатации по классу атаки.
    * :class:`TimingOracle` — оракул для time-based blind SQLi.
    * :class:`CombinedOracle` — точка входа для Stage-4 orchestrator.
    * :class:`OracleVerdict` / :class:`OracleReason` — итоговая модель решения.
"""

from __future__ import annotations

from .backend_oracle import BackendOracle
from .combined import CombinedOracle, OracleReason, OracleVerdict
from .timing_oracle import TimingOracle
from .waf_oracle import WafOracle

__all__ = [
    "BackendOracle",
    "CombinedOracle",
    "OracleReason",
    "OracleVerdict",
    "TimingOracle",
    "WafOracle",
]
