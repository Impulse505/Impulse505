# AMHF — Limitations and Self-Criticism

Документ целенаправленно собирает ограничения текущей реализации и
направления будущей работы 

## 1. Объём (scope)

- **Reinforcement learning и LLM-мутаторы выведены за рамки работы.**
  AMHF не реализует RL-policy и не использует языковые модели для
  генерации обхода. Это сознательное проектное решение: scope проекта
  ограничен классическими mutation-based техниками и bandit-обучением
  (см. §11). RL и LLM рассматриваются как смежные направления для
  сравнения, но вне scope.
- **Полная WAFFLED-таксономия не покрыта.** AMHF реализует 31 технику
  мутации, покрывающую основные публичные категории WAFFLED
  (arXiv:2503.10846), но не все описанные в статье трансформации.
  Не реализованы: header-folding (RFC 7230 §3.2.4), tricks с
  Transfer-Encoding и CRLF в значениях заголовков выше уже включённого
  `transfer_encoding_collision`, фрагментация HTTP/2 frame'ов. Эти
  направления зарезервированы в `MutatorId` Literal под будущие RFC
  и могут быть добавлены без изменений в scheduler/oracle.

## 2. Покрытие WAF

- **Полевая верификация — два движка.** Эксперименты
  используют ModSecurity + OWASP CRS (paranoia 1 и paranoia 2) и
  NAXSI 1.6. Эти два WAF выбраны как качественно разные парадигмы:
  rule/score (ModSec/CRS) и whitelist/score (NAXSI). Любая
  асимметрия bypass-rate между ними — атрибут движка, а не приложения
  (backend один и тот же).
- **Nemesida WAF Free — opt-in.** Дистрибуция Nemesida требует
  ручной регистрации в их apt-репозитории, что нарушает
  «one-command reproducibility» стенда. Конфигурация поставляется
  отключённой по умолчанию; порты 8082/8092 зарезервированы. Включить —
  два-шаговый рецепт в `stand/nemesida/README.md`. Это оставляет
  третий промышленный WAF в качестве extensibility-демонстрации, а
  не headline-числа.

## 3. Backends

- **Headline-числа — Flag-app.** Все ключевые экспериментальные
  показатели измеряются на Flag-app, маленьком Flask-сервисе с
  детерминированными маркерами (`AMHF_FLAG_`, `amhf_cmd_marker`,
  `amhf_canary_v1`). Это критично для дискриминации «WAF пропустил
  запрос» vs. «эксплойт сработал»: только литеральная подстрока в
  ответе подтверждает успех. Отсюда чистый сигнал, отсутствующий у
  настоящих CMS.
- **DVWA — extensibility-демонстрация, не measured.** DVWA включён
  в стенд как «настоящее уязвимое приложение», но не используется
  для headline-чисел: DVWA требует интерактивного PHPSESSID-логина
  и переключения security-level, которые сейчас выполняются
  одноразовым `dvwa-init` контейнером, а не самим оркестратором.
  Future work: добавить `LoginConfig` в `EndpointConfig` со схемой
  «POST → token → cookie persistence», реализовать pre-flight в
  `Orchestrator.from_config`. Это ~ 100-150 LOC и unit-test pack;
  сделано не было ради удержания scope проекта.

## 4. Корпус payload'ов

- 264 записи (sqli=80, xss=80, cmdi=51, pathtrav=53). Источники —
  PortSwigger, OWASP Testing Guide, PayloadsAllTheThings, Stuttard &
  Pinto, *The Web Application Hacker's Handbook* (2nd ed.).
- Некоторые экзотические трансформации (UTF-7 charset, overlong
  UTF-8 в путях, Unicode normalization tricks) представлены, но не
  exhaustively. Корпус намеренно расширяемый — schema разрешает
  добавление без изменения кода.

## 5. Concurrency-модель планировщика

- **Asynchronous batch UCB.** `next_batch(k)` возвращает top-k по
  текущему priority **без** внутрибатчевой переоценки (см.
  `docs/ALGORITHMS.md` § 2.6). Это компромисс: классический
  sequential UCB оптимален, но синхронен; параллельные запросы AMHF
  требуют пакетной выборки. Цена: при `concurrency ≫ pool_size`
  одна и та же рука появляется в батче многократно. Рекомендация:
  держать `concurrency ≤ pool_size`.
- Future work: pessimistic UCB (Chapelle/Li 2011) или Thompson
  sampling — оба корректно работают в parallel-online setting, но
  требуют per-arm posterior, что усложняет код в 1.5–2 раза.

## 6. Time-based blind detection

- `TimingOracle` реализует простой порог `mean + k·σ` по baseline-выборке
  (см. `amhf/oracle/timing_oracle.py`). Это grade-school оценка с
  очевидными ограничениями: чувствительна к heavy-tail latency,
  оценивает σ по малой выборке (default `n=20`). На реальной сети
  даёт false-positive ~ 1-3 % при `k=3`.
- Future work: bootstrap CI или Mann-Whitney U-test (непараметрический
  rank-test) — оба переносимы и дают tighter false-positive при
  фактически меньшем числе baseline-замеров. Реализация — отдельный
  `TimingOracle.from_bootstrap(latencies, alpha=0.001)` фабрика.

## 7. Resume-функциональность

- `scheduler_state.json` round-trips счётчики UCB1 (`n`, `sum_reward`,
  `last_played_at`) и весь пул arms. **Не** round-trips RNG-состояние
  GA: после `--resume` GA при следующей эпохе использует
  `seed_manager.fresh(...)` стрим, а это даёт другую последовательность
  бросков, чем оригинальный run.
- Последствие: bypass-rate числа после resume не воспроизводимы
  bit-by-bit относительно single-shot run на тех же n attempts.
  Документировано; для академических экспериментов используется
  single-shot режим без resume.
- Future work: persistance per-component RNG state через
  `SeedManager.spawn(name).bit_generator.state` round-trip + строгая
  ассерция в `import_state`. Не сделано ради удержания scope Stage 4.

## 8. Воспроизводимость стенда

- `vulnerables/web-dvwa` пиннуется только по тегу `latest` —
  Docker-образ официально не поддерживается, и не существует digest
  pin'а. Принято решение принять плавающий тег и зафиксировать дату
  pull'а в `stand/README.md` § «Pull dates». Любая будущая
  репродукция эксперимента, обнаружившая отличия, должна работать с
  digest-snapshot вместо вызова `docker pull`.
- ModSec + CRS, NAXSI и MariaDB — нормально pinned-by-tag/version.

## 9. Покрытие тестами

- Aggregate coverage: ~ 91 % (270 тестов на момент Stage 6).
- Per-module floor — все целевые модули ≥ 70 %, согласно принятой
  политике покрытия (per-module *и* aggregate).
- `amhf/utils/logging.py` — 50 %. Production-выполнение этого модуля
  идёт через интеграционные тесты оркестратора, а не unit-тесты;
  принимаемый trade-off (юнит-тесты на сам logging.setup_logging
  тривиальны и не дают информационной ценности).
- В рамках Stage 6 покрытие `reflection_check.py` поднято с 68 % до
  88 %.

## 10. Статистическая значимость экспериментов

- **Stage 4 (e2e_adaptive).** 3 seed'а × 500 attempt'ов × (adaptive,
  random) = 3 000 attempt'ов на сторону. Медианное соотношение
  `adaptive_rate / random_rate ≥ 2.0` — load-bearing assertion
  bench-теста. Per-seed разброс ratio ≈ ± 0.5×.
- **Stage 6 (production grid) — multi-seed расширение.**
  Multi-seed-прогон расширил grid до 5 независимых seed'ов
  ({42, 137, 256, 1024, 2026}) × 12 сценариев × 2 000 attempt'ов +
  3 FPR-сценария × 200 attempt'ов = 123 000 attempt'ов. Между seed'ами —
  `docker compose down -v && up` для холодного старта DVWA-БД и
  чистой повторной калибровки `TimingOracle`. Доверительные
  интервалы построены: для каждой пары (scenario × WAF) считается
  пуленный Wilson 95 % CI на бинальной доле, плюс per-seed
  mean / std для оценки seed-to-seed дисперсии. Артефакты:
  `results/summary_multi_seed.csv` и
  `results/charts/{bypass_rate_by_scenario,fpr_legitimate_traffic,bypass_rate_distribution}.png`
  с error-bars и boxplot'ами.

### Achievements (multi-seed расширение)

- Multi-seed grid (5 × 12 + 5 × 3 = 75 прогонов) выполнен; код
  `amhf/`, FROZEN-контракты и v0.1.0-архитектура не изменялись.
- `scripts/run_multi_seed.py` — обёртка с docker-cycling между seed'ами
  (down -v / up / poll healthy / run / повтор), вошедшая в репозиторий.
- `scripts/collect_results.py` расширен функциями `wilson_ci`,
  `per_seed_rates`, `pooled_summary`, `write_multi_seed_table`,
  `chart_bypass_rate_distribution`. Все покрыты юнит-тестами в
  `tests/unit/test_collect_results.py` (9 test cases, edge-coverage:
  `n=0` clamp, large-n-Wald-equivalence, divergent-seed std).

## 11. Out-of-scope направления

- Интеграция с CI-конвейером (`amhf` как лимит-проверка для
  внешних репозиториев) — out of scope, AMHF — не CI-tool.
- Plugin-система для собственных мутаторов через entry_points — не
  реализована, но `Mutator` Protocol + `RegistryOfMutators.register`
  поддерживают это «по форме»; Stage 4 коммит просто не разворачивает
  pyproject `[project.entry-points]` группу.

---

Cross-references:
- Концептуальные ограничения dependency-stack: `pyproject.toml`.
- Контракты, которые помечены FROZEN и менять можно только через RFC
  (`MutatorId`, `Layer`, `Mutator` Protocol, `FuzzRequest/Response`,
  `AttemptRecord`, `Chromosome`, Config schema, CLI surface) — см.
  `docs/ARCHITECTURE.md` § «FROZEN compatibility contract».
