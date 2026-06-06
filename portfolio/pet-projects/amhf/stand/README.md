# AMHF — Docker test stand

<a id="en"></a>
**English** · [Русский](#ru)

Reproducible WAF + backend test environment for the AMHF research project.
Run on Windows + Docker Desktop with WSL2 backend (verified on 29.4.0,
compose v5.1.1) or any Linux host with `docker compose`.

## Topology

```
            host                          amhf-net (bridge)
        +---------+
        |  8080   |---------> [modsec-dvwa]  --->  [dvwa]  --->  [mariadb]
        |  8081   |---------> [naxsi-dvwa]   ---/    |
        |  8082*  |---------> [nemesida-dvwa]--/     |
        |         |                                  | (init runs once: dvwa-init)
        |  8090   |---------> [modsec-flag]  --->  [flag-app] (markers)
        |  8091   |---------> [naxsi-flag]   ---/
        |  8092*  |---------> [nemesida-flag]--/
        +---------+
                       *) ports 8082 / 8092 are reserved for Nemesida and
                          require manual enablement, see stand/nemesida/README.md
```

The Nemesida pair is **disabled by default** (private apt repo + license).
Stage-5 minimum is ModSec + NAXSI + DVWA + Flag-app on 4 ports.

## Port table

| Host | Behind WAF        | Backend  | Status   |
|------|-------------------|----------|----------|
| 8080 | ModSec + CRS v4   | DVWA     | active   |
| 8081 | NAXSI 1.6         | DVWA     | active   |
| 8082 | Nemesida WAF Free | DVWA     | disabled |
| 8090 | ModSec + CRS v4   | Flag-app | active   |
| 8091 | NAXSI 1.6         | Flag-app | active   |
| 8092 | Nemesida WAF Free | Flag-app | disabled |
| —    | (internal)        | MariaDB  | active   |
| —    | (internal)        | Flag-app | active   |

## Credentials

- DVWA admin: `admin` / `password` (vendor default; the init container also
  switches DVWA to security level "low" automatically).
- MariaDB root: `amhf_root` (only on amhf-net, never exposed).
- DVWA app DB: user `dvwa` / password `p@ssw0rd`.

## Commands

### Linux / macOS / WSL

```sh
make stand-up      # docker compose up -d --build
make stand-down    # docker compose down
make stand-reset   # down -v + up --build (wipes volumes)
```

### Windows PowerShell

```powershell
.\tasks.ps1 stand-up
.\tasks.ps1 stand-down
.\tasks.ps1 stand-reset
```

### Smoke validation

```sh
python scripts/smoke_stand.py
```

The validator polls the host ports until ready, verifies the 264-entry corpus
loads, sends benign + malicious traffic through every active WAF, and uses
`docker exec amhf-flag-app curl ...` to confirm the literal markers exist.
Exit code 0 only if every row passes.

## Version pin table

| Component             | Pinned to                                      | Notes |
|-----------------------|------------------------------------------------|-------|
| MariaDB               | `mariadb:10.11.10`                             | LTS line; supports DVWA's MySQL protocol |
| DVWA                  | `vulnerables/web-dvwa:latest`                  | Image is unmaintained; we accept the floating tag and document the pull date here |
| ModSec + CRS          | `owasp/modsecurity-crs:4.25.0-nginx-alpine-lts` | CRS v4.25.0 on nginx-alpine LTS. Paranoia level 1. |
| NAXSI                 | built from source, NAXSI git tag `1.6`, nginx 1.26.2 | Compiled as a static module against `wargio/naxsi` |
| Nemesida WAF Free     | 4.x (built only after license registration)    | Disabled by default; see `stand/nemesida/README.md` |
| Flag-app base         | `python:3.12-slim`                             | gunicorn + Flask 3 |
| dvwa-init base        | `alpine:3.19`                                  | One-shot init container |

Pull dates / digests should be appended here when refreshing the stand.

## How to add a new WAF (extensibility note)

1. Create `stand/<waf-name>/Dockerfile` that installs the WAF in front of nginx
   and proxies to `http://${BACKEND_HOST}:${BACKEND_PORT}/`.
2. Add a `<waf-name>-dvwa` and `<waf-name>-flag` pair to
   `stand/docker-compose.yml`, each with `BACKEND_HOST` set respectively to
   `dvwa` or `flag-app`. Pick two free ports from the 8083-8089 / 8093-8099 range.
3. Update the port table in this file and `docs/STAND.md`.
4. Extend `scripts/smoke_stand.py` `PORTS_DVWA` / `PORTS_FLAG` dicts to include
   the new WAF; benign + malicious checks pick it up automatically.

The stand is designed so adding a fourth WAF is an afternoon's work, not a
rewrite.

## Known limitations

1. **DVWA image is unmaintained.** `vulnerables/web-dvwa` has not been pushed
   in a long time. We rely on it because it is the canonical DVWA
   image. If you want a maintained alternative, swap to `vulnerables/cve-2017-7494`-style
   bespoke images per attack class — but this would invalidate the
   "DVWA baseline" comparison.
2. **Nemesida is opt-in.** See `stand/nemesida/README.md`.
3. **NAXSI build is from source.** First `docker compose build` will take
   several minutes because nginx is recompiled. Subsequent builds are cached.
4. **No HTTPS.** All ports are plain HTTP — the stand is internal-only. For
   local demos this is acceptable; AMHF itself does not care about TLS.

---

<a id="ru"></a>

# AMHF — Docker-стенд

[English](#en) · **Русский**

Воспроизводимая тестовая среда WAF + бэкенд для исследовательского проекта AMHF.
Запускается на Windows + Docker Desktop с бэкендом WSL2 (проверено на 29.4.0,
compose v5.1.1) либо на любом Linux-хосте с `docker compose`.

## Топология

```
            host                          amhf-net (bridge)
        +---------+
        |  8080   |---------> [modsec-dvwa]  --->  [dvwa]  --->  [mariadb]
        |  8081   |---------> [naxsi-dvwa]   ---/    |
        |  8082*  |---------> [nemesida-dvwa]--/     |
        |         |                                  | (init runs once: dvwa-init)
        |  8090   |---------> [modsec-flag]  --->  [flag-app] (markers)
        |  8091   |---------> [naxsi-flag]   ---/
        |  8092*  |---------> [nemesida-flag]--/
        +---------+
                       *) ports 8082 / 8092 are reserved for Nemesida and
                          require manual enablement, see stand/nemesida/README.md
```

Пара Nemesida **отключена по умолчанию** (приватный apt-репозиторий + лицензия).
Минимум для Stage-5 — это ModSec + NAXSI + DVWA + Flag-app на 4 портах.

## Таблица портов

| Host | Behind WAF        | Backend  | Status   |
|------|-------------------|----------|----------|
| 8080 | ModSec + CRS v4   | DVWA     | active   |
| 8081 | NAXSI 1.6         | DVWA     | active   |
| 8082 | Nemesida WAF Free | DVWA     | disabled |
| 8090 | ModSec + CRS v4   | Flag-app | active   |
| 8091 | NAXSI 1.6         | Flag-app | active   |
| 8092 | Nemesida WAF Free | Flag-app | disabled |
| —    | (internal)        | MariaDB  | active   |
| —    | (internal)        | Flag-app | active   |

## Учётные данные

- Администратор DVWA: `admin` / `password` (значение по умолчанию от
  поставщика; init-контейнер также автоматически переключает DVWA на уровень
  безопасности "low").
- Root MariaDB: `amhf_root` (только в сети amhf-net, наружу никогда не
  пробрасывается).
- БД приложения DVWA: пользователь `dvwa` / пароль `p@ssw0rd`.

## Команды

### Linux / macOS / WSL

```sh
make stand-up      # docker compose up -d --build
make stand-down    # docker compose down
make stand-reset   # down -v + up --build (wipes volumes)
```

### Windows PowerShell

```powershell
.\tasks.ps1 stand-up
.\tasks.ps1 stand-down
.\tasks.ps1 stand-reset
```

### Дымовая проверка

```sh
python scripts/smoke_stand.py
```

Валидатор опрашивает порты хоста до их готовности, проверяет загрузку корпуса
из 264 записей, отправляет безвредный + вредоносный трафик через каждый
активный WAF и с помощью `docker exec amhf-flag-app curl ...` подтверждает
наличие буквальных маркеров. Код возврата 0 выдаётся только если проходит
каждая строка.

## Таблица закреплённых версий

| Component             | Pinned to                                      | Notes |
|-----------------------|------------------------------------------------|-------|
| MariaDB               | `mariadb:10.11.10`                             | LTS line; supports DVWA's MySQL protocol |
| DVWA                  | `vulnerables/web-dvwa:latest`                  | Image is unmaintained; we accept the floating tag and document the pull date here |
| ModSec + CRS          | `owasp/modsecurity-crs:4.25.0-nginx-alpine-lts` | CRS v4.25.0 on nginx-alpine LTS. Paranoia level 1. |
| NAXSI                 | built from source, NAXSI git tag `1.6`, nginx 1.26.2 | Compiled as a static module against `wargio/naxsi` |
| Nemesida WAF Free     | 4.x (built only after license registration)    | Disabled by default; see `stand/nemesida/README.md` |
| Flag-app base         | `python:3.12-slim`                             | gunicorn + Flask 3 |
| dvwa-init base        | `alpine:3.19`                                  | One-shot init container |

При обновлении стенда сюда следует дописывать даты загрузки / дайджесты.

## Как добавить новый WAF (заметка о расширяемости)

1. Создайте `stand/<waf-name>/Dockerfile`, который ставит WAF перед nginx
   и проксирует на `http://${BACKEND_HOST}:${BACKEND_PORT}/`.
2. Добавьте пару `<waf-name>-dvwa` и `<waf-name>-flag` в
   `stand/docker-compose.yml`, у каждой задайте `BACKEND_HOST` соответственно
   в `dvwa` или `flag-app`. Выберите два свободных порта из диапазона
   8083-8089 / 8093-8099.
3. Обновите таблицу портов в этом файле и в `docs/STAND.md`.
4. Расширьте словари `PORTS_DVWA` / `PORTS_FLAG` в `scripts/smoke_stand.py`,
   включив новый WAF; безвредные + вредоносные проверки подхватят его
   автоматически.

Стенд спроектирован так, что добавление четвёртого WAF — это работа на полдня,
а не переписывание с нуля.

## Известные ограничения

1. **Образ DVWA не сопровождается.** `vulnerables/web-dvwa` давно не
   публиковался. Мы полагаемся на него, поскольку это канонический образ
   DVWA. Если нужна сопровождаемая альтернатива, перейдите на собственные
   образы в стиле `vulnerables/cve-2017-7494` под каждый класс атак — но это
   обесценит сравнение с "базовой линией DVWA".
2. **Nemesida подключается по желанию.** См. `stand/nemesida/README.md`.
3. **Сборка NAXSI из исходников.** Первый `docker compose build` займёт
   несколько минут, потому что nginx перекомпилируется. Последующие сборки
   кэшируются.
4. **Без HTTPS.** Все порты — это обычный HTTP, стенд предназначен только для
   внутреннего использования. Для локальных демонстраций это приемлемо; самому
   AMHF до TLS дела нет.
