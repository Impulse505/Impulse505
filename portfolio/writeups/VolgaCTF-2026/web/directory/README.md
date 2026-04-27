# Directory (Web) — VolgaCTF 2026

## English

### Challenge Description
The **Directory** web challenge was an LDAP-based directory service. The application implemented a search functionality that was vulnerable to **Blind Boolean-Based LDAP Injection**.

### Vulnerability Analysis
The search endpoint used the following LDAP filter construction:
`(|(uid={username})(mail={email}))`

By inputting a crafted payload in the `email` field, I could alter the query's behavior. For example, using `NOTHING*)(&(uid=admin)(mail=a*)` resulted in the filter:
`(|(uid=nobody)(mail=NOTHING*)( &(uid=admin)(mail=a*) ))`

This allowed for data extraction by checking if the server returned `{"exists": true}`.

### Exploitation Process
1.  **User Enumeration**: I brute-forced the attributes of the `admin` user but found it was disabled. I then performed a broader search to identify another account: `asmith`.
2.  **Attribute Extraction**: Using the injection vulnerability, I extracted `asmith`'s email and telephone number.
3.  **Authentication**: After logging in as `asmith` and then an `operator`, I gained access to more privileged directory branches.
4.  **Retrieving the Flag**: By querying the `/directory?ou=secret` organizational unit, I successfully extracted the flag.

### Exploit Script

```python
# exploit.py 
# (Blind LDAP injection strategy)
import requests

def check_condition(payload):
    data = {"username": "nobody", "email": f"NOTHING*)(&{payload})"}
    r = requests.post(URL, json=data)
    return "exists" in r.text
# ...
```


### Flag
`VolgaCTF{dn_1nj3ct10n_br34ks_ld4p_b0und4r13s_2025}`

---

## Russian

### Описание задания
Веб-задание **Directory** представляло собой корпоративный сервис директорий на базе LDAP. Поиск в приложении оказался уязвим к **Blind Boolean-Based LDAP Injection** (слепым логическим LDAP-инъекциям).

### Анализ уязвимости
Эндпоинт поиска использовал следующую конструкцию фильтра:
`(|(uid={username})(mail={email}))`

Отправляя специально сформированный пейлоад в поле `email`, мне удалось изменить логику запроса. Например, пейлоад `NOTHING*)(&(uid=admin)(mail=a*)` превращал фильтр в:
`(|(uid=nobody)(mail=NOTHING*)( &(uid=admin)(mail=a*) ))`

Это позволило извлекать данные посимвольно, анализируя ответы сервера `{"exists": true}`.

### Процесс эксплуатации
1.  **Enumeration пользователей**: Сначала я перечислил атрибуты `admin`, но аккаунт был отключен. Затем я нашел включенный аккаунт: `asmith`.
2.  **Извлечение атрибутов**: Используя уязвимость, я узнал email и номер телефона `asmith`.
3.  **Аутентификация**: Авторизовавшись под `asmith`, а затем под `operator`, я получил доступ к более закрытым веткам директории.
4.  **Получение флага**: Запрос к подразделению (OU) `secret` позволил успешно извлечь спрятанный флаг.

### Скрипт эксплоита

```python
# exploit.py
# (Использование LDAP injection для слепого извлечения данных)
# ... аналогично версии на английском ...
```


### Флаг
`VolgaCTF{dn_1nj3ct10n_br34ks_ld4p_b0und4r13s_2025}`
