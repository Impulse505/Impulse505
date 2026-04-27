# NoOneChilled (Web) — AlfaCTF 2026

## English

### Challenge Description
**NoOneChilled** was a web application for employees to communicate with their boss. The goal was to retrieve the boss's "vacation code" (the flag) which was available via a restricted API endpoint.

### Vulnerability Analysis
The application used Nginx as a reverse proxy with a caching configuration for static files (ending in `.jpg`, `.png`, etc.). 

**Vulnerabilities:**
1. **SSRF via Boss Bot**: The boss would visit any URL sent to them in a private message. The bot used an authenticated session (cookies).
2. **Nginx Cache Poisoning**: Nginx was configured to cache responses for URLs ending in `.jpg`. If a requested file was not found on disk, it fell back to a `@cache` location which proxied the request to the backend API.

**The Attack Chain:**
1. The attacker identifies a sensitive API endpoint: `/xhr/api/auth/vacation-code`.
2. The attacker appends a fake extension: `/xhr/api/auth/vacation-code/exploit.jpg`.
3. The attacker sends this URL to the boss.
4. When the boss visits the URL, Nginx proxies the request to the backend. The backend ignores the trailing `/exploit.jpg` or treats it as a parameter, and returns the boss's sensitive JSON response.
5. Nginx sees the `.jpg` extension and **caches** the response (the boss's JSON).
6. The attacker then requests the same URL `/xhr/api/auth/vacation-code/exploit.jpg` and receives the cached response containing the boss's flag.

### Exploitation Process
1. **Register** as a regular employee.
2. **Start a DM** with the "Boss" user.
3. **Send the URL**: `http://no-one-chilled.alfactf.ru/xhr/api/auth/vacation-code/flag.jpg`.
4. **Wait** for the boss to visit (indicated by the "seen" status or a small delay).
5. **Retrieve Flag**: `curl http://no-one-chilled.alfactf.ru/xhr/api/auth/vacation-code/flag.jpg`.

### Flag
`alfa{chilL_R3aRm_chIlL_ReARm_cHIll_r3arm_CHilL}`

---

## Russian

### Описание задания
**NoOneChilled** — веб-приложение для общения сотрудников с руководством. Цель — получить "код отпуска" (флаг) босса, доступный через защищенный API-эндпоинт.

### Анализ уязвимости
Приложение использовало Nginx в качестве прокси-сервера с настроенным кэшированием для статических файлов (с расширениями `.jpg`, `.png` и т.д.).

**Уязвимости:**
1. **SSRF через бот-аккаунт босса**: Босс переходил по любым ссылкам, присланным ему в личные сообщения. Бот использовал аутентифицированную сессию (куки босса).
2. **Отравление кэша Nginx (Cache Poisoning)**: Nginx кэшировал ответы для URL, оканчивающихся на `.jpg`. Если файл не находился на диске, запрос перенаправлялся на бэкенд через локацию `@cache`.

**Цепочка атаки:**
1. Атакующий находит чувствительный эндпоинт: `/xhr/api/auth/vacation-code`.
2. Атакующий добавляет фиктивное расширение: `/xhr/api/auth/vacation-code/exploit.jpg`.
3. Атакующий отправляет эту ссылку боссу в личные сообщения.
4. Когда босс переходит по ссылке, Nginx проксирует запрос на бэкенд. Бэкенд возвращает JSON-ответ с данными босса.
5. Nginx, видя расширение `.jpg`, **сохраняет этот ответ в кэш**.
6. Атакующий запрашивает тот же URL `/xhr/api/auth/vacation-code/exploit.jpg` и получает из кэша ответ, предназначавшийся боссу, в котором содержится флаг.

### Процесс эксплуатации
1. **Регистрация** обычного сотрудника.
2. **Создание чата** с пользователем "Boss".
3. **Отправка ссылки**: `http://no-one-chilled.alfactf.ru/xhr/api/auth/vacation-code/flag.jpg`.
4. **Ожидание** перехода босса по ссылке.
5. **Получение флага**: `curl http://no-one-chilled.alfactf.ru/xhr/api/auth/vacation-code/flag.jpg`.

### Флаг
`alfa{chilL_R3aRm_chIlL_ReARm_cHIll_r3arm_CHilL}`
