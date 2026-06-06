# AMHF — Configuration Reference

Полный справочник YAML-схемы AMHF. Каждая секция конфига отражает один
pydantic v2 класс из `amhf/config.py`; неизвестные ключи **отвергаются
сразу** (`extra="forbid"`), все объекты `frozen=True`.

Канонический шаблон — `configs/default.yaml`. Сценарные конфиги
(`configs/scenarios/*.yaml`) описывают только дельту относительно него.

Команда валидации без запуска:

```sh
python -m amhf validate -c configs/default.yaml
```

---

## 1. `run:`

Параметры одного запуска эксперимента.

| Ключ                | Тип       | Default | Допустимые | Назначение |
|---------------------|-----------|---------|------------|------------|
| `total_requests`    | int (>0)  | —       | ≥ 1        | Полный бюджет попыток фаззинга. |
| `concurrency`       | int (>0)  | —       | ≥ 1        | Размер in-flight батча (см. § «asynchronous batch UCB»). |
| `request_timeout_s` | float (>0)| —       | > 0        | Таймаут одного HTTP-запроса в секундах. |
| `rate_limit_rps`    | float (>0)| —       | > 0        | Глобальный лимит RPS на исходящие запросы. |
| `seed`              | int       | —       | любой      | Master seed для всего эксперимента (см. `SeedManager`). |
| `resume_from`       | str\|null | `null`  | путь, имя  | Папка предыдущего run'а для возобновления (читает `scheduler_state.json`). |

Примечание про `concurrency`. Внутрибатчевой переоценки приоритетов
UCB1 нет (см. `docs/ALGORITHMS.md` § 2.6); если `concurrency ≫
pool_size`, в одном батче будут дубликаты одной руки.

---

## 2. `target:`

Описание системы под фаззингом.

| Ключ        | Тип              | Default | Назначение |
|-------------|------------------|---------|------------|
| `name`      | str              | —       | Человекочитаемое имя цели (попадает в `AttemptRecord.target_id`). |
| `base_url`  | str              | —       | Базовый URL без `/` в конце; пути эндпоинтов конкатенируются к нему. |
| `endpoints` | list[Endpoint]   | min=1   | Список эндпоинтов; должен содержать хотя бы один. |

### 2.1 `target.endpoints[]` — `EndpointConfig`

| Ключ              | Тип                                                                     | Default | Назначение |
|-------------------|-------------------------------------------------------------------------|---------|------------|
| `path`            | str                                                                     | —       | Путь относительно `base_url`. |
| `method`          | enum `GET\|POST\|PUT\|DELETE\|PATCH\|HEAD\|OPTIONS`                     | —       | HTTP-метод. |
| `params`          | dict[str,str]                                                           | `{}`    | Query-параметры по умолчанию (стартовое значение `param_to_fuzz`). |
| `attack_class`    | enum `sqli\|xss\|cmdi\|pathtrav`                                        | —       | Класс атаки — выбирает соответствующий backend-handler оракула. |
| `param_to_fuzz`   | str                                                                     | —       | Имя параметра, в который payload-слой подставляет мутации. |
| `session_cookie`  | str \| null                                                             | `null`  | Заголовок Cookie для DVWA-style эндпоинтов (PHPSESSID + security=low). |
| `body_template`   | str \| null                                                             | `null`  | Тело запроса (для POST/PUT) — стартовая точка для body-мутаторов. |

---

## 3. `corpus:`

| Ключ           | Тип                                            | Default | Назначение |
|----------------|------------------------------------------------|---------|------------|
| `paths`        | list[Path], min=1                              | —       | YAML-файлы корпуса; обычно `corpus/<class>.yaml`. |
| `filter_class` | enum `sqli\|xss\|cmdi\|pathtrav` \| null       | `null`  | Загружать только записи указанного класса. |
| `max_payloads` | int \| null                                    | `null`  | Жёсткий лимит количества payload'ов (бутстрап-режим). |

---

## 4. `scheduler:`

| Ключ                    | Тип                                          | Default | Назначение |
|-------------------------|----------------------------------------------|---------|------------|
| `type`                  | enum `ucb_with_ga\|ucb1_only\|uniform`       | —       | Полная адаптивка vs. raw UCB1 vs. uniform. На Stage 6 используется `ucb_with_ga`. |
| `initial_pool_size`     | int (>0)                                     | —       | Стартовая мощность пула; должен быть ≥ `concurrency`. |
| `max_chromosome_length` | int (>0, ≤5)                                 | —       | Жёсткий потолок длины хромосомы (FROZEN — `Chromosome` контракт). |
| `ucb_c`                 | float (>0)                                   | —       | Коэффициент при `sqrt(2·ln N / n_i)`; `1.41 = √2` — каноническое значение. |
| `ga`                    | object                                       | —       | Вложенная секция (см. ниже). |

### 4.1 `scheduler.ga` — `GAConfig`

| Ключ                     | Тип                | Default | Назначение |
|--------------------------|--------------------|---------|------------|
| `period`                 | int (>0)           | —       | Каждые `period` accepted attempt'ов запускается GA-эпоха. |
| `top_k`                  | int (>0)           | —       | Сколько лучших рук берётся в родители. |
| `offspring_per_round`    | int (>0)           | —       | Скольких потомков пытается породить один проход GA. |
| `p_replace`              | float [0,1]        | 0.10    | Per-gene вероятность замены гена. |
| `p_insert`               | float [0,1]        | 0.05    | Per-chromosome вероятность вставки гена. |
| `p_delete`               | float [0,1]        | 0.05    | Per-chromosome вероятность удаления гена. |
| `min_plays_for_selection`| int (≥0)           | 3       | Минимальное `n` руки, при котором она допускается в родители. |

Установка `period` в значение `> total_requests` отключает GA-эпохи
полностью — это режим baseline (см. сценарии `s1_…` и `s2_…`).

---

## 5. `mutators:`

Четыре списка идентификаторов из контракта `MutatorId`. Хотя бы один
список должен быть непуст (валидатор `_at_least_one_mutator`).

| Ключ        | Тип                | Default | Назначение |
|-------------|--------------------|---------|------------|
| `payload`   | list[MutatorId]    | `[]`    | Алфавит payload-слоя. |
| `body`      | list[MutatorId]    | `[]`    | Алфавит body-слоя. |
| `headers`   | list[MutatorId]    | `[]`    | Алфавит headers-слоя. |
| `url`       | list[MutatorId]    | `[]`    | Алфавит url-слоя. |

### 5.1 Полный алфавит `MutatorId`

Источник: `amhf/mutators/base.py:22-36`. **31 идентификатор, 4 слоя.**

#### Payload (12) — `amhf/mutators/payload.py`

| ID                | Что делает                                                        |
|-------------------|-------------------------------------------------------------------|
| `url_encode`      | Percent-encoding всех символов кроме ASCII alnum.                |
| `double_url_encode`| Двойной percent-encoding.                                        |
| `html_entity`     | `&#NN;` для каждого символа.                                      |
| `unicode_escape`  | `\uNNNN` для каждого символа (JS-style).                          |
| `hex_encode`      | `\xNN` для каждого UTF-8-байта.                                   |
| `base64`          | base64 от UTF-8 байтов.                                           |
| `comment_inject`  | Вставка SQL-комментария `/**/` в случайную позицию.               |
| `case_toggle`     | `swapcase` всей строки.                                           |
| `whitespace_tricks`| Замена пробела на TAB / VT / FF / NL / CR.                       |
| `null_byte`       | Дописывает `%00` в конец.                                         |
| `keyword_fragment`| Разрывает SQL-keywords (`UNION`, `SELECT`, …) комментарием.       |
| `charset_trick`   | UTF-7 кодирование payload'а.                                      |

#### Body (7) — `amhf/mutators/body.py`

| ID                  | Что делает                                                              |
|---------------------|-------------------------------------------------------------------------|
| `multipart_boundary`| Конвертирует form-body в `multipart/form-data` с random boundary.       |
| `charset_juggle`    | Подменяет `charset` в `Content-Type` (`ibm500`).                        |
| `param_pollution`   | HPP — дублирует `param_to_fuzz` в теле.                                 |
| `json_form_swap`    | `application/x-www-form-urlencoded` → `application/json`. Excludes: `multipart_boundary`, `param_pollution`, `content_type_swap`. |
| `content_type_swap` | `Content-Type: text/plain` без переформатирования. Excludes: `json_form_swap`. |
| `gzip_encode`       | gzip-сжимает тело + `Content-Encoding: gzip`. Excludes: `chunked_encode`. |
| `chunked_encode`    | `Transfer-Encoding: chunked`. Excludes: `gzip_encode`.                  |

#### Headers (6) — `amhf/mutators/headers.py`

| ID                            | Что делает                                                |
|-------------------------------|-----------------------------------------------------------|
| `duplicate`                   | Добавляет `X-Original-URL` со значением = path+query.    |
| `case_jiggle`                 | Случайно перемешивает регистр в именах заголовков.       |
| `transfer_encoding_collision` | `Transfer-Encoding: chunked, identity` (request smuggling). |
| `xff_spoof`                   | Случайный RFC1918 IP в `X-Forwarded-For`.                |
| `accept_encoding_trick`       | `Accept-Encoding: identity;q=0,*;q=1`.                   |
| `host_header_trick`           | Добавляет `X-Forwarded-Host: evil.example`.              |

#### URL (6) — `amhf/mutators/url.py`

| ID                  | Что делает                                                      |
|---------------------|-----------------------------------------------------------------|
| `method_case`       | `GET` → `Get` (нестандартный регистр метода).                  |
| `path_normalize`    | Внедряет `/a/..` в начало пути.                                 |
| `percent_encode_path`| Все символы пути кодируются как `%NN`.                         |
| `segment_inject`    | Добавляет `;jsessionid=…` к последнему сегменту.                |
| `fragment_inject`   | Добавляет `#amhf` в конец URL.                                  |
| `query_encoding`    | Полный percent-encoding ключей и значений query.                |

**Default-rule совместимости (FROZEN).** В пределах одного слоя любые
два различных мутатора несовместимы (контракт «один мутатор на слой
на хромосому»). Дополнительные явные исключения — в колонке
«Excludes» выше; full-text — в `docs/ARCHITECTURE.md` §
«Compatibility contract».

---

## 6. `oracle:`

### 6.1 `oracle.waf` — `WafOracleConfig`

| Ключ                       | Тип             | Default | Назначение |
|----------------------------|-----------------|---------|------------|
| `blocked_codes`            | list[int]       | `[]`    | HTTP-коды, при которых попытка считается заблокированной. Типично `[403, 406, 418, 419, 501]`. |
| `blocked_body_signatures`  | list[str]       | `[]`    | Подстроки в теле ответа — сигнатуры WAF-стенд (`ModSecurity`, `NAXSI`, `Forbidden`, `Access Denied`, …). |
| `block_page_size_max`      | int (>0)        | 4096    | ModSec иногда возвращает 200 с маленькой блок-страницей; этот hint позволяет распознать «короткое 200 = block». |

### 6.2 `oracle.backend` — `BackendOracleConfig`

| Ключ                           | Тип       | Default | Назначение |
|--------------------------------|-----------|---------|------------|
| `timing_k`                     | float (>0)| 3.0     | k для `mean + k·σ` в TimingOracle (порог time-based blind). |
| `timing_baseline_min_samples`  | int (≥5)  | 20      | Минимальное число baseline-замеров для калибровки. |
| `sqli`                         | object    | —       | См. § 6.2.1. |
| `xss`                          | object    | —       | См. § 6.2.2. |
| `cmdi`                         | object    | —       | См. § 6.2.3. |
| `pathtrav`                     | object    | —       | См. § 6.2.4. |

#### 6.2.1 `oracle.backend.sqli` — `SqliOracleConfig`

| Ключ                       | Тип        | Default            | Назначение |
|----------------------------|------------|--------------------|------------|
| `error_signatures`         | list[str]  | `[]`               | DB-error фразы (`You have an error in your SQL syntax`, `PostgreSQL`, `ORA-`, `SQLite`). |
| `flag_marker`              | str        | `"AMHF_FLAG_"`     | Литеральная подстрока успеха SQLi (Flag-app). |
| `time_delay_threshold_ms`  | float (>0) | 2500.0             | Fixed-fallback порог для TimingOracle, если калибровка не вышла. |

#### 6.2.2 `oracle.backend.xss` — `XssOracleConfig`

| Ключ              | Тип   | Default | Назначение |
|-------------------|-------|---------|------------|
| `reflection_check`| bool  | `true`  | Включает контентную проверку отражения payload'а (см. `amhf/oracle/reflection_check.py`). |

#### 6.2.3 `oracle.backend.cmdi` — `CmdiOracleConfig`

| Ключ              | Тип  | Default               | Назначение |
|-------------------|------|-----------------------|------------|
| `command_marker`  | str  | `"amhf_cmd_marker"`   | Литеральная подстрока успеха CMDi (Flag-app выводит маркер из argv-subprocess). |

#### 6.2.4 `oracle.backend.pathtrav` — `PathTravOracleConfig`

| Ключ              | Тип  | Default              | Назначение |
|-------------------|------|----------------------|------------|
| `canary_marker`   | str  | `"amhf_canary_v1"`   | Содержимое канареечного файла `/etc/amhf_canary` для подтверждения LFI. |

---

## 7. `storage:`

| Ключ          | Тип                            | Default | Назначение |
|---------------|--------------------------------|---------|------------|
| `output_dir`  | str (template)                 | —       | Куда писать `attempts.{csv,db,jsonl}`. Поддерживает шаблон `{timestamp}`. |
| `formats`     | list[`csv\|sqlite\|jsonl`], min=1 | —    | Какие sinks открыть. Можно указывать несколько. |
| `flush_every` | int (>0)                       | —       | Через сколько записей делать flush (сжимает risk потери при KeyboardInterrupt). |

---

## 8. `logging:`

| Ключ              | Тип                                  | Default  | Назначение |
|-------------------|--------------------------------------|----------|------------|
| `level`           | enum `DEBUG\|INFO\|WARNING\|ERROR`    | `INFO`   | Уровень root-логгера AMHF. |
| `json_file`       | str \| null                          | `null`   | Если задано — структурированный JSONL-лог в этот файл (поддерживает `{timestamp}`). |
| `human_console`   | bool                                 | `true`   | Включает rich-форматированную консоль. |

---

## 9. Сценарии Stage 6 — diff к `default.yaml`

Все 12 production-сценариев (`configs/scenarios/sN_<name>_<waf>_flag.yaml`)
наследуют общий каркас из `default.yaml` и отличаются только параметрами
поиска и WAF-таргетом. Ниже — характерные дельты.

### 9.1 `s1_baseline_*` (без мутаций)

```diff
 target:
-  base_url: http://localhost:8080
+  base_url: http://localhost:809{0|1|3}     # WAF-flag триплет
 scheduler:
-  initial_pool_size: 30
+  initial_pool_size: 1                       # один-арм бандит
-  max_chromosome_length: 5
+  max_chromosome_length: 1
   ga:
-    period: 200
+    period: 2100                              # > total_requests = OFF
 mutators:
   payload:
-    - url_encode
-    - double_url_encode
-    - … (8 ids)
+    - case_toggle                            # один тривиальный мутатор
   body: []
   headers: []
   url: []
```

Назначение: estabilish a baseline bypass-rate для каждой пары
(WAF, backend) — нужна для расчёта относительного выигрыша адаптивной
схемы.

### 9.2 `s2_single_layer_*` (только payload-слой)

```diff
 scheduler:
-  initial_pool_size: 30
+  initial_pool_size: 8                       # 8 single-gene payload-arms
-  max_chromosome_length: 5
+  max_chromosome_length: 1
   ga:
-    period: 200
+    period: 2100                              # GA off
 mutators:
   payload:
-    - … (8 ids, default)
+    - url_encode, double_url_encode, html_entity, hex_encode,
+      case_toggle, comment_inject, keyword_fragment, null_byte
   body: []
   headers: []
   url: []
```

### 9.3 `s3_multi_layer_*` (4 слоя, GA выключен)

```diff
 scheduler:
-  initial_pool_size: 30
+  initial_pool_size: 20
-  max_chromosome_length: 5
+  max_chromosome_length: 4
   ga:
-    period: 200
+    period: 2100                              # GA off
 mutators:
   payload: [8 ids]
   body:    [param_pollution, content_type_swap]
   headers: [case_jiggle, duplicate]
   url:     [path_normalize, percent_encode_path]
```

Назначение: сравнить «slot-machine UCB1 без эволюции» против полного
адаптивного режима s4.

### 9.4 `s4_adaptive_*` (полный AMHF — UCB1+GA)

```diff
 scheduler:
   initial_pool_size: 30
   max_chromosome_length: 5
   ga:
     period: 200                                # один эпоха каждые 200 attempt'ов
     top_k: 6
     offspring_per_round: 4
     p_replace: 0.10, p_insert: 0.05, p_delete: 0.05
 mutators:                                      # full default alphabet
   payload: [8 ids], body: [2], headers: [2], url: [2]
```

Это и есть «headline» AMHF — числа из этой группы идут как основные
результаты.

---

## 10. Программный API

```python
from amhf.config import Config, load_config

cfg: Config = load_config("configs/default.yaml")
print(cfg.run.total_requests)
print(cfg.scheduler.ga.p_replace)
```

Ошибки валидации (`pydantic.ValidationError`) поднимаются с точным
указанием пути ключа. CLI-команда `amhf validate -c <file>`
оборачивает это в exit-code 2 с человекочитаемым сообщением.
