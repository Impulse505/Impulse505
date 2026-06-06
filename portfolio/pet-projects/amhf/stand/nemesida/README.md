# Nemesida WAF Free — disabled by default in the AMHF stand

<a id="en"></a>
**English** · [Русский](#ru)

## Honest status

Nemesida WAF Free (Pentestit) ships its core packages through a **private apt
repository** that requires (a) registration on https://nemesida-waf.com and
(b) a per-host license key issued after that registration. It is *not* available
as a public Docker Hub image with permissive terms.

For a fully reproducible research stand we therefore ship Nemesida **disabled by
default** in `stand/docker-compose.yml`: a documented fallback with a clear,
self-service path to enable it (below).

Stage-5 minimum is **ModSecurity + NAXSI + DVWA + Flag-app** (4 services,
ports 8080 / 8081 / 8090 / 8091). Nemesida is added in Stage-6 if the
researcher obtains a license — see below.

## How to enable it on your machine

1. Register at https://nemesida-waf.com and download the apt-source `.list`
   plus the GPG key. You will receive credentials in the format
   `deb https://nemesida-security.com/nemesida-waf-free/<distro> <distro> non-free`.
2. Drop the credentials into `stand/nemesida/secret/nemesida.list` and the GPG
   key into `stand/nemesida/secret/nemesida.gpg` (this folder is `.gitignore`d).
3. Build the image yourself with `docker compose -f stand/docker-compose.yml \
   -f stand/nemesida/docker-compose.fragment.yml build nemesida-dvwa nemesida-flag`.
4. Bring the stand up with both compose files:
   `docker compose -f stand/docker-compose.yml -f stand/nemesida/docker-compose.fragment.yml up -d`.

The fragment file `docker-compose.fragment.yml` adds the two Nemesida services
to the base stack on ports 8082 / 8092.

## Versions targeted

If/when you build it, target Nemesida WAF Free 4.x (the current line as of
2026-04). State the exact version on your machine in your write-up.



---

<a id="ru"></a>

# Nemesida WAF Free — по умолчанию отключён в стенде AMHF

[English](#en) · **Русский**

## Честный статус

Nemesida WAF Free (Pentestit) распространяет свои основные пакеты через
**приватный apt-репозиторий**, который требует (а) регистрации на
https://nemesida-waf.com и (б) лицензионного ключа на каждый хост, выдаваемого
после этой регистрации. Он *не* доступен как публичный образ Docker Hub с
разрешительными условиями.

Поэтому для полностью воспроизводимого исследовательского стенда мы поставляем
Nemesida **отключённым по умолчанию** в `stand/docker-compose.yml`: это
документированный запасной вариант с понятным самостоятельным способом его
включения (ниже).

Минимум для Stage-5 — это **ModSecurity + NAXSI + DVWA + Flag-app** (4 сервиса,
порты 8080 / 8081 / 8090 / 8091). Nemesida добавляется в Stage-6, если
исследователь получит лицензию — см. ниже.

## Как включить его на своей машине

1. Зарегистрируйтесь на https://nemesida-waf.com и скачайте apt-источник `.list`
   вместе с GPG-ключом. Вы получите учётные данные в формате
   `deb https://nemesida-security.com/nemesida-waf-free/<distro> <distro> non-free`.
2. Поместите учётные данные в `stand/nemesida/secret/nemesida.list`, а GPG-ключ
   в `stand/nemesida/secret/nemesida.gpg` (эта папка добавлена в `.gitignore`).
3. Соберите образ самостоятельно командой `docker compose -f stand/docker-compose.yml \
   -f stand/nemesida/docker-compose.fragment.yml build nemesida-dvwa nemesida-flag`.
4. Поднимите стенд с обоими compose-файлами:
   `docker compose -f stand/docker-compose.yml -f stand/nemesida/docker-compose.fragment.yml up -d`.

Файл-фрагмент `docker-compose.fragment.yml` добавляет два сервиса Nemesida
к базовому стеку на портах 8082 / 8092.

## Целевые версии

Если/когда вы будете его собирать, ориентируйтесь на Nemesida WAF Free 4.x
(актуальная линейка по состоянию на 2026-04). Укажите точную версию на вашей
машине в своём отчёте.


