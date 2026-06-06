# Lab — Vulnerable Service Stand

<a id="en"></a>
**English** · [Русский](#ru)

A `docker-compose.yml` stand of intentionally vulnerable services used to
exercise the scanner end-to-end without touching real infrastructure.

> **Do not run this on a network you don't own.** Every container here ships
> a public CVE on purpose.

## Containers

| Service              | Image                                     | Host port | Reference CVE         |
|----------------------|-------------------------------------------|-----------|-----------------------|
| Apache 2.4.49        | `httpd:2.4.49`                            | 8081      | CVE-2021-41773        |
| vsftpd               | `fauria/vsftpd:latest`                    | 2121      | demo FTP banner       |
| MySQL 5.7            | `mysql:5.7`                               | 13306     | multiple historical   |
| OpenSSH              | `linuxserver/openssh-server:9.3_p1-r3-ls132` | 2222   | demo SSH fingerprint  |

Host ports are mapped to non-default values so they don't collide with sshd,
Apache, or MySQL that might already run on the box.

## Bring the stand up

```bash
cd lab
docker compose up -d
docker compose ps         # confirm health
```

## Run the scanner against the lab

From the project root:

```bash
python cli.py \
    --target 127.0.0.1 \
    --ports 8081,2121,13306,2222 \
    --output all \
    --output-file scan_results/lab.json \
    --html-output scan_results/lab.html
```

The HTML report ends up at `scan_results/lab.html` — open it in a browser
to see the per-host expandable detail panes with CVSS-coloured CVE rows.

## Tear it down

```bash
cd lab
docker compose down -v
```

## Known caveats

* `httpd:2.4.49` is no longer on Docker Hub's "official" filter, but the
  tag itself remains pullable. If the pull fails, swap in
  `vulhub/httpd:2.4.49` instead — both ship the vulnerable build.
* The `fauria/vsftpd` image does not pin to vsftpd 2.3.4; we use it to
  exercise the FTP banner classifier. To reproduce the historical 2.3.4
  backdoor (CVE-2011-2523), build from `vulhub/vsftpd-2.3.4` and adjust
  the port mapping.

---

<a id="ru"></a>

# Lab — стенд уязвимых сервисов

[English](#en) · **Русский**

Стенд на `docker-compose.yml` из намеренно уязвимых сервисов — нужен, чтобы
прогонять сканер end-to-end, не затрагивая реальную инфраструктуру.

> **Не запускайте это в сети, которой вы не владеете.** Каждый контейнер здесь
> намеренно содержит публичную CVE.

## Контейнеры

| Сервис               | Образ                                     | Порт хоста | Эталонная CVE         |
|----------------------|-------------------------------------------|-----------|-----------------------|
| Apache 2.4.49        | `httpd:2.4.49`                            | 8081      | CVE-2021-41773        |
| vsftpd               | `fauria/vsftpd:latest`                    | 2121      | демо FTP-баннер       |
| MySQL 5.7            | `mysql:5.7`                               | 13306     | много исторических    |
| OpenSSH              | `linuxserver/openssh-server:9.3_p1-r3-ls132` | 2222   | демо SSH-отпечаток    |

Порты хоста намеренно нестандартные, чтобы не конфликтовать с sshd, Apache или
MySQL, которые уже могут работать на машине.

## Поднять стенд

```bash
cd lab
docker compose up -d
docker compose ps         # проверить health
```

## Запустить сканер по стенду

Из корня проекта:

```bash
python cli.py \
    --target 127.0.0.1 \
    --ports 8081,2121,13306,2222 \
    --output all \
    --output-file scan_results/lab.json \
    --html-output scan_results/lab.html
```

HTML-отчёт окажется в `scan_results/lab.html` — открой его в браузере, чтобы
увидеть раскрывающиеся панели по каждому хосту со строками CVE, подсвеченными
по CVSS.

## Остановить и удалить

```bash
cd lab
docker compose down -v
```

## Известные нюансы

* `httpd:2.4.49` больше не проходит фильтр «official» на Docker Hub, но сам
  тег по-прежнему скачивается. Если pull не удался — подставь
  `vulhub/httpd:2.4.49`: оба образа содержат уязвимую сборку.
* Образ `fauria/vsftpd` не зафиксирован на vsftpd 2.3.4; мы используем его,
  чтобы прогнать классификатор FTP-баннеров. Чтобы воспроизвести исторический
  бэкдор 2.3.4 (CVE-2011-2523), собери из `vulhub/vsftpd-2.3.4` и поправь
  маппинг портов.
