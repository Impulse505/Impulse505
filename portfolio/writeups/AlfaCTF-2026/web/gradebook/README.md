# gradebook (Web/Crypto) — alfaCTF 2026

## English

### Challenge Description
The **gradebook** challenge was a Go-based server that accepted a YAML gradebook file. To get the flag, the file needed to contain only perfect grades (5s), but its custom rolling polynomial hash had to exactly match the hash of an original reference file (which contained lower grades).

### Vulnerability Analysis
- **YAML Comment Injection**: YAML ignores comments (anything after `#`). This allows appending arbitrary bytes to the end of the file without breaking the parsing logic.
- **Custom Hash Reversibility**: The server used a custom polynomial hash over `GF(2^56 - 5)`. Because the modulus is a prime and the hash is just a polynomial evaluation, it's possible to append a small amount of padding and solve a linear equation to find the exact suffix bytes needed to collide with the target hash.
- **Constraints**: The appended suffix must not contain a newline (`\n`) and must consist only of valid printable ASCII characters to pass the Go `yaml.v3` parser UTF-8 validation.

### Exploitation Process
1. **Creating the Base Payload**: I constructed a YAML file with all grades set to 5 and appended a newline followed by `# ` to start a comment block.
2. **Hash Collision Script**: I wrote a Python script to compute the hash of this prefix and solve for the remaining 7 bytes required to match the target hash.
3. **Padding and Brute-forcing**: The script systematically padded the comment with valid ASCII characters (`?`) until the necessary 7-byte suffix was completely within the printable ASCII range.
4. **Flag Retrieval**: Sending the forged YAML file with the crafted suffix to the server successfully bypassed the signature check and returned the flag.

### Solve Script
```python
# solve.py
# (Script to calculate hash collisions and forge the YAML payload)
# ... see full solve.py file for details ...
```

### Flag
`alfa{attES7A7_V_krOVI_po_B0kAm_koNV0y_A_m3NyA_V3su7_P0d_S1reni_v0Y}`

---

## Russian

### Описание задания
Задание **gradebook** представляло собой сервер на Go, принимающий YAML-файл аттестата. Для получения флага файл должен был содержать только пятерки, однако его кастомный полиномиальный хеш должен был в точности совпадать с хешем оригинального файла (где были тройки и четверки).

### Анализ уязвимости
- **Внедрение YAML-комментариев**: YAML игнорирует комментарии (все, что идет после `#`). Это позволяет добавлять произвольные байты в конец файла, не ломая логику парсинга.
- **Обратимость кастомного хеша**: Сервер использовал кастомный полиномиальный хеш над полем `GF(2^56 - 5)`. Поскольку модуль является простым числом, можно добавить небольшой паддинг и решить линейное уравнение, чтобы найти точные байты суффикса для коллизии с целевым хешем.
- **Ограничения**: Добавляемый суффикс не должен содержать переносов строки (`\n`) и должен состоять только из печатных ASCII-символов, чтобы пройти валидацию UTF-8 парсера Go `yaml.v3`.

### Процесс эксплуатации
1. **Создание базовой нагрузки**: Я создал YAML-файл, в котором все оценки были исправлены на 5, и добавил в конец перенос строки и `# ` для начала блока комментария.
2. **Скрипт коллизии хеша**: Я написал скрипт на Python для вычисления хеша этого префикса и подбора оставшихся 7 байт, необходимых для совпадения с целевым хешем.
3. **Паддинг и перебор**: Скрипт перебирал паддинг из валидных ASCII-символов (`?`), пока необходимые 7 байт суффикса полностью не попадали в диапазон печатных символов.
4. **Получение флага**: Отправка поддельного YAML-файла со сгенерированным суффиксом на сервер успешно обошла проверку подписи и позволила получить флаг.

### Скрипт решения
```python
# solve.py
# (Скрипт для вычисления коллизии хеша и подделки YAML-файла)
# ... полная версия в файле solve.py ...
```

### Флаг
`alfa{attES7A7_V_krOVI_po_B0kAm_koNV0y_A_m3NyA_V3su7_P0d_S1reni_v0Y}`
