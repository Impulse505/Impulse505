# AMHF Payload Corpus

<a id="en"></a>
**English** · [Русский](#ru)

A set of seed payloads for the AMHF tool, developed as part of a bachelor's thesis on the topic "Research and implementation of a WAF-bypass methodology based on generating adaptive and obfuscated HTTP requests".

## Purpose

The corpus contains "reference" payloads for four attack classes: SQLi, XSS, Command Injection, and Path Traversal. These payloads are the starting points for the AMHF mutation layer — for each of them, the tool's scheduler generates obfuscated variants aimed at bypassing the WAF.

All payloads are published in open educational sources (cheat sheets, OWASP, academic publications) and are used exclusively for academic and defensive purposes to test the author's own test stands.

## File structure

| File | Attack class | Records |
|------|--------------|---------|
| `sqli.yaml` | SQL Injection | 80 |
| `xss.yaml` | Cross-Site Scripting | 80 |
| `cmdi.yaml` | OS Command Injection | 51 |
| `pathtrav.yaml` | Path Traversal / LFI | 53 |
| **Total** | — | **264** |

## Record format

Each YAML record is a dictionary with a fixed set of fields:

```yaml
- id: sqli_taut_001                        # unique identifier
  class: sqli                              # one of {sqli, xss, cmdi, pathtrav}
  payload: "' OR '1'='1"                   # the payload itself as a string
  description: Classic tautology           # short human-readable description
  expected_markers:                        # markers of successful exploitation
    - "AMHF_FLAG_"
    - "Welcome"
  difficulty: trivial                      # trivial | easy | medium | hard
  source: PortSwigger SQLi Cheat Sheet     # source
```

### The `expected_markers` field

Contains substrings that the `BackendOracle` looks for in the response body to confirm successful exploitation (not merely passing through the WAF).

Special markers:
- `AMHF_FLAG_` — the stand's Flag-app service prints the string `AMHF_FLAG_<row>` on a successful SQL injection.
- `amhf_cmd_marker` — a string printed by the stand in response to a successful command injection.
- `amhf_canary_v1` — the contents of the canary file `/etc/amhf_canary` for path-traversal attacks.
- `__TIME_DELAY__` — a pseudo-marker for time-based payloads; handled separately by the oracle (based on the actual response delay).
- `__STACKED_OK__` — a pseudo-marker for stacked queries.

### The `difficulty` field

Used by AMHF for two purposes:
1. Balancing the initial chromosome pool (priority from simpler → harder).
2. Grouping results (bypass rate by difficulty level).

## Ethical disclaimer

The corpus is intended exclusively for:
- Testing the author's own WAF stands in an isolated virtual environment.
- Educational use within academic work.
- Research purposes in the field of web application security.

Using it against systems that do not belong to the researcher or that lack written permission for testing is not allowed.

## Sources

- PortSwigger Web Security Academy — Cheat Sheets and Labs.
- OWASP Testing Guide v4.2 — Web Security Testing Guide.
- PayloadsAllTheThings — Public collection of educational payloads.
- Stuttard D., Pinto M. The Web Application Hacker's Handbook (2nd ed., Wiley, 2011).

## Extending the corpus

The corpus is intentionally made extensible. To add new payloads:

1. Open the corresponding YAML.
2. Add a record with a unique `id` (format: `{class}_{group}_{NNN}`).
3. Specify all required fields.
4. Run `python -m amhf validate corpus/<file>.yaml`.
5. Commit.

---

<a id="ru"></a>

# AMHF — корпус payload'ов

[English](#en) · **Русский**

Массив базовых payload-нагрузок для инструмента AMHF, разрабатываемого в рамках дипломной работы по теме «Исследование и реализация методики обхода WAF на основе генерации адаптивных и обфусцированных HTTP-запросов».

## Назначение

Корпус содержит «эталонные» payload-нагрузки для четырёх классов атак: SQLi, XSS, Command Injection и Path Traversal. Эти payload-ы являются стартовыми точками для слоя мутаций AMHF — по каждому из них планировщик инструмента генерирует обфусцированные варианты с целью обхода WAF.

Все нагрузки опубликованы в открытых учебных источниках (cheat sheets, OWASP, академические публикации) и используются исключительно в академических и оборонительных целях для тестирования собственных стендов.

## Структура файлов

| Файл | Класс атаки | Записей |
|------|-------------|---------|
| `sqli.yaml` | SQL Injection | 80 |
| `xss.yaml` | Cross-Site Scripting | 80 |
| `cmdi.yaml` | OS Command Injection | 51 |
| `pathtrav.yaml` | Path Traversal / LFI | 53 |
| **Итого** | — | **264** |

## Формат записи

Каждая запись YAML — словарь с фиксированным набором полей:

```yaml
- id: sqli_taut_001                        # уникальный идентификатор
  class: sqli                              # один из {sqli, xss, cmdi, pathtrav}
  payload: "' OR '1'='1"                   # сама нагрузка как строка
  description: Классическая тавтология     # краткое описание на русском
  expected_markers:                        # маркеры успешной эксплуатации
    - "AMHF_FLAG_"
    - "Welcome"
  difficulty: trivial                      # trivial | easy | medium | hard
  source: PortSwigger SQLi Cheat Sheet     # источник
```

### Поле `expected_markers`

Содержит подстроки, которые `BackendOracle` ищет в теле ответа для подтверждения успешной эксплуатации (а не только пропуска через WAF).

Специальные маркеры:
- `AMHF_FLAG_` — Flag-app-сервис стенда выводит строку `AMHF_FLAG_<row>` при успешной SQL-инъекции.
- `amhf_cmd_marker` — строка, выводимая стендом в ответ на успешную command-injection.
- `amhf_canary_v1` — содержимое канареечного файла `/etc/amhf_canary` для path-traversal-атак.
- `__TIME_DELAY__` — псевдо-маркер для time-based-payload-ов; обрабатывается оракулом отдельно (по фактической задержке ответа).
- `__STACKED_OK__` — псевдо-маркер для stacked-queries.

### Поле `difficulty`

Используется AMHF для двух целей:
1. Балансировка стартового пула хромосом (приоритет проще → сложнее).
2. Группировка результатов (taux обхода по уровням сложности).

## Этический дисклеймер

Корпус предназначен исключительно для:
- Тестирования собственных WAF-стендов в изолированной виртуальной среде.
- Образовательного использования в рамках академической работы.
- Исследовательских целей в области защиты веб-приложений.

Использование против систем, не принадлежащих исследователю или не имеющих письменного разрешения на тестирование, — недопустимо.

## Источники

- PortSwigger Web Security Academy — Cheat Sheets and Labs.
- OWASP Testing Guide v4.2 — Web Security Testing Guide.
- PayloadsAllTheThings — Public collection of educational payloads.
- Stuttard D., Pinto M. The Web Application Hacker's Handbook (2nd ed., Wiley, 2011).

## Расширение корпуса

Корпус намеренно сделан расширяемым. Для добавления новых нагрузок:

1. Открыть соответствующий YAML.
2. Добавить запись с уникальным `id` (формат: `{class}_{group}_{NNN}`).
3. Указать все обязательные поля.
4. Прогнать `python -m amhf validate corpus/<file>.yaml`.
5. Закоммитить.
