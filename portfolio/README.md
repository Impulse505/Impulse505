<div align="center">

# Vladislav Batursev

### Junior Web Pentester

**Russia / Remote** &nbsp;·&nbsp; 4th-year Information Security student

[![Telegram](https://img.shields.io/badge/Telegram-@Impulse575-26A5E4?style=flat&logo=telegram&logoColor=white)](https://t.me/Impulse575)
[![GitHub](https://img.shields.io/badge/GitHub-Impulse505-181717?style=flat&logo=github&logoColor=white)](https://github.com/Impulse505)
[![Email](https://img.shields.io/badge/Email-batursevvlad%40gmail.com-D14836?style=flat&logo=gmail&logoColor=white)](mailto:batursevvlad@gmail.com)
[![CTFTime](https://img.shields.io/badge/CTFTime-Impulse505-red?style=flat)](https://ctftime.org/user/240334)

</div>

---

## 🧑‍💻 About Me

> Hi — I'm Vlad, a fourth-year Information Security student focused on web application security. Most of my writeups are web, but at CTFs I also take pwn, crypto, reverse, and stego challenges. Outside of CTFs, I'm steadily expanding my skills through courses and hands-on labs. Real-world side: 6 confirmed pentest findings reported with CVSS (detailed below), a thesis on WAF bypass techniques, and 18 writeups from VolgaCTF 2026 and AlfaCTF 2026. Comfortable in Python, JS and Bash.

---

## 🔎 Real-World Pentest Findings

Vulnerabilities responsibly disclosed in production web applications, reported with CVSS scores:

- **Broken Access Control** — admin-only functionality reachable without proper authorization checks.
- **IDOR** — insecure direct object reference exposing other users' data.
- **Privilege Escalation** — an admin endpoint that authorized requests solely on a client-supplied `admin: true` field (a forgeable role flag).
- **Business-Logic Flaw** — missing uniqueness enforcement let a single account register for the same event multiple times.
- **User Enumeration** — authentication responses that reveal whether an account exists.

---

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-000000?style=for-the-badge&logo=owasp&logoColor=white)
![Web Security](https://img.shields.io/badge/Web%20Security-8A2BE2?style=for-the-badge&logo=hackthebox&logoColor=white)

---

## 🚩 CTF Writeups

*Detailed solutions and exploitation scripts from various Capture The Flag competitions.*

### 🅰️ [AlfaCTF 2026](./writeups/AlfaCTF-2026/)


| Category | Challenge | Topic |
|----------|-----------|-------|
| 🌐 Web | [chococore](./writeups/AlfaCTF-2026/web/chococore/README.md) | JavaScript type coercion in API logic |
| 🌐 Web | [Dress Code](./writeups/AlfaCTF-2026/web/dresscode/README.md) | SQL Injection & AES-CBC IV Malleability |
| 🌐 Web | [NoOneChilled](./writeups/AlfaCTF-2026/web/no-one-chilled/README.md) | Nginx Cache Poisoning via SSRF |
| 🌐 Web | [Basecamp](./writeups/AlfaCTF-2026/web/basecamp/README.md) | Race Condition → Mutex Deadlock in Go |
| 🌐 Web | [cat](./writeups/AlfaCTF-2026/web/cat/README.md) | Client-side DOM/CSS protection bypass |
| 🌐 Web | [capital](./writeups/AlfaCTF-2026/web/capital/README.md) | LFI, ML model extraction & backdoor |
| 🌐 Web | [dragon_tea](./writeups/AlfaCTF-2026/web/dragon_tea/README.md) | Password logic reverse & utf-7 filter bypass |
| 🌐 Web | [gradebook](./writeups/AlfaCTF-2026/web/gradebook/README.md) | Polynomial hash collision & YAML injection |
| 🔄 Reverse | [Terminal](./writeups/AlfaCTF-2026/reverse/terminal/README.md) | GF(251) matrix math & custom stream cipher |
| 🛠️ Misc | [Redflag](./writeups/AlfaCTF-2026/misc/redflag/README.md) | Path confusion in terminal SSH app |

---

### 🛡️ [VolgaCTF 2026](./writeups/VolgaCTF-2026/)

| Category | Challenge | Topic |
|----------|-----------|-------|
| 🌐 Web | [Directory](./writeups/VolgaCTF-2026/web/directory/README.md) | Blind Boolean-Based LDAP Injection |
| 🌐 Web | [LuckySensors](./writeups/VolgaCTF-2026/web/lucky-sensors/README.md) | Blind Boolean-Based SQL Injection |
| 🌐 Web | [NoFrontend](./writeups/VolgaCTF-2026/web/no-frontend/README.md) | API Enumeration & Brute Force |
| 💻 Pwn | [Login](./writeups/VolgaCTF-2026/pwn/login/README.md) | 32→64 bit transition & SROP exploitation |
| 💻 Pwn | [lasOS](./writeups/VolgaCTF-2026/pwn/lasos/README.md) | Kernel exploitation on a custom OS |
| 🔐 Crypto | [Happy Meal](./writeups/VolgaCTF-2026/crypto/happy-meal/README.md) | FCSR state recovery & Ethereum HD Wallet derivation |
| 🖼️ Stego | [Deep](./writeups/VolgaCTF-2026/stego/deep/README.md) | SteganoGAN decoder retraining |

---

## 🧪 Pet Projects

- **[AMHF — Adaptive Multi-layer HTTP Fuzzer](./pet-projects/amhf/)** — a research WAF-bypass fuzzer: a 4-layer mutation engine driven by a UCB1 multi-armed bandit + genetic algorithm, a dual oracle (WAF + backend + timing), and a Dockerized WAF stand (ModSecurity/CRS, NAXSI). 
- **[Subnet Scanner](./pet-projects/subnet-scanner/)** — an async network scanner with service fingerprinting and NVD/CVE lookup; finds firewalled Windows hosts via ARP + NBNS and renders CVSS-coloured HTML/JSON reports.

---

## 📜 [Certifications & Achievements](./certificates/README.md)


- **MIA CTF 2026** — 🥈 4th among universities · 7th overall
- **Student CTF 2025** — 🏅 8th in the final 
- **Regions Cup 2025** — 18th place
- **RedShift CTF 2026** — 40th place
- **KubSTU CTF 2026** — 74th, students track 
- **Alfa CTF 2026** — 103rd, CTF track 
- **DUCKERZ CTF 2026**
- **Б152** — Information Security internship (Personal Data Protection)


---

<div align="center">

## Русская версия

# Владислав Батурцев

### Junior Web Pentester

**Россия / Remote** &nbsp;·&nbsp; Студент 4 курса, "Информационная безопасность"

[![Telegram](https://img.shields.io/badge/Telegram-@Impulse575-26A5E4?style=flat&logo=telegram&logoColor=white)](https://t.me/Impulse575)
[![GitHub](https://img.shields.io/badge/GitHub-Impulse505-181717?style=flat&logo=github&logoColor=white)](https://github.com/Impulse505)
[![Email](https://img.shields.io/badge/Email-batursevvlad%40gmail.com-D14836?style=flat&logo=gmail&logoColor=white)](mailto:batursevvlad@gmail.com)
[![CTFTime](https://img.shields.io/badge/CTFTime-Impulse505-red?style=flat)](https://ctftime.org/user/240334)

</div>

---

### 🧑‍💻 Обо мне

> Привет — меня зовут Влад, я студент 4 курса по направлению "Информационная безопасность", фокус — безопасность веб-приложений. Большая часть writeup'ов про web, но на CTF беру и задания других категорий: pwn, crypto, reverse, stego. Помимо CTF активно прокачиваю знания и навыки через курсы и лабораторные. Из практики: 6 подтверждённых находок на реальных pentest'ах с CVSS (подробнее ниже), дипломная работа по обходам WAF, 18 writeup'ов с VolgaCTF 2026 и AlfaCTF 2026. Уверенно работаю с Python, JS и Bash.

---

### 🔎 Находки на реальных проектах

Уязвимости, ответственно раскрытые в production-веб-приложениях и оформленные с оценкой по CVSS:

- **Broken Access Control** — доступ к админ-функциям без должной проверки авторизации.
- **IDOR** — небезопасная прямая ссылка на объект: доступ к данным других пользователей.
- **Privilege Escalation** — админская ручка авторизовала запрос только по клиентскому полю `admin: true` (подменяемый флаг роли).
- **Business-Logic Flaw** — отсутствие проверки уникальности позволяло одному аккаунту регистрироваться на одно мероприятие несколько раз.
- **User Enumeration** — ответы аутентификации раскрывали, существует ли учётная запись.

---

### 🛠️ Технологии

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-000000?style=for-the-badge&logo=owasp&logoColor=white)
![Web Security](https://img.shields.io/badge/Web%20Security-8A2BE2?style=for-the-badge&logo=hackthebox&logoColor=white)

---

### 🚩 CTF Writeups

*Подробные разборы заданий и эксплойт-скрипты с различных Capture The Flag соревнований.*

#### 🅰️ [AlfaCTF 2026](./writeups/AlfaCTF-2026/)

| Категория | Задание | Тема |
|-----------|---------|------|
| 🌐 Web | [chococore](./writeups/AlfaCTF-2026/web/chococore/README.md) | Приведение типов JavaScript в логике API |
| 🌐 Web | [Dress Code](./writeups/AlfaCTF-2026/web/dresscode/README.md) | SQL-инъекция и AES-CBC IV malleability |
| 🌐 Web | [NoOneChilled](./writeups/AlfaCTF-2026/web/no-one-chilled/README.md) | Отравление кэша Nginx через SSRF |
| 🌐 Web | [Basecamp](./writeups/AlfaCTF-2026/web/basecamp/README.md) | Race condition → mutex deadlock на Go |
| 🌐 Web | [cat](./writeups/AlfaCTF-2026/web/cat/README.md) | Обход клиентской DOM/CSS-защиты |
| 🌐 Web | [capital](./writeups/AlfaCTF-2026/web/capital/README.md) | LFI, извлечение ML-модели и бэкдор |
| 🌐 Web | [dragon_tea](./writeups/AlfaCTF-2026/web/dragon_tea/README.md) | Реверс парольной логики и обход фильтра через utf-7 |
| 🌐 Web | [gradebook](./writeups/AlfaCTF-2026/web/gradebook/README.md) | Коллизия полиномиального хэша и YAML-инъекция |
| 🔄 Reverse | [Terminal](./writeups/AlfaCTF-2026/reverse/terminal/README.md) | Матрицы над GF(251) и кастомный поточный шифр |
| 🛠️ Misc | [Redflag](./writeups/AlfaCTF-2026/misc/redflag/README.md) | Path confusion в SSH-терминале |

---

#### 🛡️ [VolgaCTF 2026](./writeups/VolgaCTF-2026/)

| Категория | Задание | Тема |
|-----------|---------|------|
| 🌐 Web | [Directory](./writeups/VolgaCTF-2026/web/directory/README.md) | Blind Boolean-Based LDAP-инъекция |
| 🌐 Web | [LuckySensors](./writeups/VolgaCTF-2026/web/lucky-sensors/README.md) | Blind Boolean-Based SQL-инъекция |
| 🌐 Web | [NoFrontend](./writeups/VolgaCTF-2026/web/no-frontend/README.md) | API-enumeration и brute force |
| 💻 Pwn | [Login](./writeups/VolgaCTF-2026/pwn/login/README.md) | Переход 32→64 bit и SROP-эксплуатация |
| 💻 Pwn | [lasOS](./writeups/VolgaCTF-2026/pwn/lasos/README.md) | Эксплуатация ядра на кастомной ОС |
| 🔐 Crypto | [Happy Meal](./writeups/VolgaCTF-2026/crypto/happy-meal/README.md) | Восстановление состояния FCSR и Ethereum HD Wallet |
| 🖼️ Stego | [Deep](./writeups/VolgaCTF-2026/stego/deep/README.md) | Переобучение декодера SteganoGAN |

---

### 🧪 Pet-проекты

- **[AMHF — Adaptive Multi-layer HTTP Fuzzer](./pet-projects/amhf/)** — исследовательский фаззер для обхода WAF: 4-слойный движок мутаций под управлением UCB1-бандита и генетического алгоритма, dual-oracle (WAF + backend + timing) и Docker-стенд с WAF (ModSecurity/CRS, NAXSI). 
- **[Subnet Scanner](./pet-projects/subnet-scanner/)** — асинхронный сетевой сканер с фингерпринтингом сервисов и поиском CVE через NVD; находит зафаерволенные Windows-хосты через ARP + NBNS и строит HTML/JSON-отчёты с подсветкой по CVSS.

---

### 📜 [Сертификаты и достижения](./certificates/README.md)

- **MIA CTF 2026** — 🥈 4-е место среди вузов · 7-е в общем зачёте
- **Студент CTF 2025** — 🏅 8-е место в финале 
- **Кубок регионов 2025** — 18-е место
- **RedShift CTF 2026** — 40-е место
- **KubSTU CTF 2026** — 74-е место, студенческий зачёт 
- **Альфа CTF 2026** — 103-е место, CTF-трек 
- **DUCKERZ CTF 2026**
- **Б152** — стажировка по ИБ (защита персональных данных)

---

*Last updated: June 2026*
