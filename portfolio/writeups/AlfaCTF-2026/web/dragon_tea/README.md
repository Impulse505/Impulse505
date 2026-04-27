# Dragon Tea (Web) — alfaCTF 2026

## English

### Challenge Description
The **Dragon Tea** web challenge consisted of two stages. The first stage involved local reverse engineering of encrypted data, and the second stage was a web service that executed Python code under the strict condition that every line of the file started with a comment character `#`.

### Vulnerability Analysis
- **Weak Password Verification**: The password validation `bytes([n + 1 for n in sys.argv[1].encode()]).upper() == b'IJSBLFHPNB'` was easily reversible to discover the first password.
- **Code Hiding (Mojibake)**: The challenge script had a massive trailing comment that concealed a Python script when decoded from `cp866` to `cp500`.
- **Comment Filter Bypass**: Python's `utf-7` encoding feature can be abused. By using `# coding: utf-7`, characters like `+AAo-` are interpreted as newlines by Python but are seen as part of a comment by the simplistic `#` validation filter.

### Exploitation Process
1. **Reversing Phase 1**: I reversed the logic and derived the first password "hirakegoma", decrypting a hint.
2. **Reversing Phase 2**: I extracted the hidden script from the mojibake comment and found the password "himetahimitsu", which revealed the target URL for the web challenge.
3. **Bypassing the Filter**: To execute code on the server, I provided a script beginning with `# coding: utf-7` and injected my payload using `+AAo-` to simulate a newline.
4. **Flag Retrieval**: I injected a file read command `#+AAo-print(open("/sandbox/flag.txt").read())` to execute code and retrieve the flag.

### Solve Script
```python
# solve.py
# (Payload script to exploit utf-7 comment bypass and read the flag)
# ... see full solve.py file for details ...
```

### Flag
`alfa{M4in_fr4MES_Are_coMpi3x_Bu7_cUt3}`

---

## Russian

### Описание задания
Веб-задание **Dragon Tea** ("Чай Дракона") состояло из двух этапов. Первый этап включал локальный реверс-инжиниринг зашифрованных блоков данных, а второй — веб-сервис, выполняющий код на Python при строгом условии, что каждая строка файла начинается с символа комментария `#`.

### Анализ уязвимости
- **Слабая проверка пароля**: Условие проверки `bytes([n + 1 for n in sys.argv[1].encode()]).upper() == b'IJSBLFHPNB'` было легко обратимо для нахождения первого пароля.
- **Сокрытие кода (Mojibake)**: В конце файла находился огромный мусорный комментарий. Если перекодировать его из `cp866` в `cp500`, восстанавливался скрытый Python-скрипт.
- **Обход фильтра комментариев**: Использование `utf-7` кодировки в Python (`# coding: utf-7`) позволяет интерпретатору парсить конструкцию `+AAo-` как перевод строки. При этом валидатор по-прежнему считает строку комментарием.

### Процесс эксплуатации
1. **Реверс Часть 1**: Я реверсировал проверку и нашел первый пароль "hirakegoma", расшифровав подсказку.
2. **Реверс Часть 2**: Я извлек скрытый скрипт из mojibake-комментария, получил пароль "himetahimitsu" и узнал целевой URL веб-таска.
3. **Обход фильтра**: Для выполнения кода на сервере я отправил скрипт с заголовком `# coding: utf-7`, внедрив полезную нагрузку через `+AAo-` для переноса строки.
4. **Получение флага**: Я внедрил команду на чтение файла `#+AAo-print(open("/sandbox/flag.txt").read())` и успешно получил флаг.

### Скрипт решения
```python
# solve.py
# (Полезная нагрузка для обхода фильтра комментариев через utf-7 и чтения флага)
# ... полная версия в файле solve.py ...
```

### Флаг
`alfa{M4in_fr4MES_Are_coMpi3x_Bu7_cUt3}`
