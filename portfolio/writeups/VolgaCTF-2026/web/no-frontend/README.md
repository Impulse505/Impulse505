# NoFrontend (Web) — VolgaCTF 2026

## English

### Challenge Description
The **NoFrontend** web challenge was a backend-only application consisting of a set of API endpoints. There was no user interface, and the goal was to exploit the authentication and authorization mechanism.

### Vulnerability Analysis
- **API Enumeration**: By exploring the endpoints, I discovered a `/auth` route for user login. 
- **Incorrect RBAC**: The application had an RBAC (Role-Based Access Control) system, but it was possible to enumerate existing users. 
- **Brute Force**: I found that the `user1` account existed and was susceptible to password brute-forcing.

### Exploitation Process
1.  **Scanning for Endpoints**: I used automated tools to discover the hidden API structure. 
2.  **Brute-Forcing Credentials**: I wrote a Python script to perform a systematic brute-force attack on the `/auth` endpoint until I found the password for `user1`.
3.  **Flag Retrieval**: Once authenticated, I gained access to a restricted area of the API to retrieve the flag.

### Solve Script

```python
# solve.py
import urllib.request
import json

def req(payload):
    data = json.dumps(payload).encode()
    r = urllib.request.Request(URL, data=data, headers={'Content-Type': 'application/json'}, method='POST')
    # ... logic to brute force usernames and passwords ...
```


### Flag
`VolgaCTF{8001347984}`

---

## Russian

### Описание задания
Веб-задание **NoFrontend** представляло собой приложение, состоящее полностью из API-эндпоинтов, без пользовательского интерфейса. Задача заключалась в обходе механизмов аутентификации и авторизации.

### Анализ уязвимости
- **Enumeration эндпоинтов**: При исследовании структуры API был обнаружен маршрут `/auth`.
- **Ошибки RBAC**: В системе управления ролями (RBAC) была допущена ошибка, позволившая перечислить существующих пользователей.
- **Brute Force**: Выяснилось, что аккаунт `user1` существует и к нему можно подобрать пароль.

### Процесс эксплуатации
1.  **Поиск эндпоинтов**: Я использовал инструменты для сканирования, чтобы восстановить скрытую структуру API.
2.  **Брутфорс учетных данных**: Я написал Python-скрипт для автоматизированного перебора паролей к эндпоинту `/auth`, пока не нашел верный пароль для `user1`.
3.  **Получение флага**: После успешной авторизации я получил доступ к защищенному разделу API, где и находился флаг.

### Скрипт решения

```python
# solve.py
# (Реализация брутфорса учетных данных через API-эндпоинт /auth)
# ... аналогично версии на английском ...
```


### Флаг
`VolgaCTF{8001347984}`
