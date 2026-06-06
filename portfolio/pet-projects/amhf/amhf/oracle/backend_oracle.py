"""BackendOracle — подтверждение эксплуатации.

Класс инкапсулирует четыре под-проверки (по числу классов атак): SQLi, XSS,
CMDi, PathTrav. Метод ``confirm`` диспетчеризует на конкретный обработчик
по полю ``attack_class`` и возвращает кортеж ``(confirmed, reason)``.

Сами проверки вынесены в ``_backend_helpers`` для компактности модуля.
"""

from __future__ import annotations

from collections.abc import Sequence

from amhf.config import BackendOracleConfig
from amhf.delivery.request import FuzzResponse

from . import _backend_helpers as _h
from .timing_oracle import TimingOracle


class BackendOracle:
    """Подтверждение эксплуатации по содержимому HTTP-ответа."""

    def __init__(
        self,
        cfg: BackendOracleConfig,
        timing: TimingOracle | None = None,
    ) -> None:
        # Сохраняем конфиг и заранее компилируем SQLi-регулярки.
        self._cfg = cfg
        self._compiled = _h.compile_patterns(cfg)
        # Если timing-оракул не передан, создаём fallback по фиксированному порогу.
        self._timing: TimingOracle = (
            timing
            if timing is not None
            else TimingOracle.from_threshold(cfg.sqli.time_delay_threshold_ms)
        )

    @property
    def timing(self) -> TimingOracle:
        """Текущий TimingOracle (для использования из CombinedOracle)."""
        return self._timing

    def set_timing(self, timing: TimingOracle) -> None:
        """Public setter — оркестратор после калибровки подсовывает живой TimingOracle.

        Альтернатива приватному self._timing-доступу из orchestrator (Stage 4
        techдолг). Контракт: timing неизменяем после установки на одном run-id;
        повторные вызовы допустимы только из калибровочной фазы.
        """
        self._timing = timing

    def confirm(
        self,
        resp: FuzzResponse,
        attack_class: str,
        *,
        payload_text: str | None = None,
        expected_markers: Sequence[str] = (),
    ) -> tuple[bool, str]:
        """Подтвердить эксплуатацию по классу атаки.

        Возвращает (confirmed, reason). ``reason`` — короткая
        человекочитаемая строка для лога/отчёта (см. ``AttemptRecord``).
        """
        # Диспетчер по классу атаки — ключевая точка модуля.
        if attack_class == "sqli":
            return _h.check_sqli(
                resp,
                self._cfg,
                self._compiled,
                expected_markers,
                self._timing,
            )
        if attack_class == "xss":
            return _h.check_xss(resp, payload_text, expected_markers)
        if attack_class == "cmdi":
            return _h.check_cmdi(resp, self._cfg)
        if attack_class == "pathtrav":
            return _h.check_pathtrav(resp, self._cfg)
        # Неизвестный класс — не подтверждаем (ошибки конфига должны падать выше).
        return (False, f"unknown attack_class: {attack_class!r}")
