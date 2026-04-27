# Terminal (Reverse) — alfaCTF 2026

## English

### Challenge Description
**Terminal** (Терминал учёта провизии) was an unusual Reverse Engineering challenge implemented entirely within a Google Spreadsheet. The spreadsheet acted as a terminal emulator featuring 8 input cells for a password and a large encrypted QR code bitmap below. The goal was to reverse-engineer the spreadsheet's logic, find the correct 8-character password, and decrypt the QR code to read the flag.

### Vulnerability Analysis & Reversing
The spreadsheet was divided into several functional sheets:
- **Panel**: The main UI containing the 8 input cells and the QR bitmap.
- **s1**: Password verification logic. This implemented a 3-layer linear transformation over `GF(251)`:
  - Layer 0: `M1 = rows40_42 @ P mod 251` (3 values)
  - Layer 1: `L1 = (W1 @ P + b1) mod 251`
  - Layer 2: `L2 = (W2a @ L1 + W2b @ P + b2) mod 251`
  - Layer 3: `L3 = (W3a @ L2 + W3b @ L1 + ... + b3) mod 251`
  - The target vector for L3 was `[92, 97, 27, 240, 199, 80, 217, 23]`.
- **s2**: A custom stream cipher (Feistel-like structure, modulo 65536) used to generate the keystream for the QR code based on the password.
- **s3**: The encrypted QR data (26×10 bytes).

### Exploitation Process
1. **Password Recovery**: Since the entire password verification process in `s1` was a combination of linear operations over `GF(251)`, we unrolled all three layers into a single linear operator `A_final ∈ GF(251)^{8×8}`. The equation `A_final @ P ≡ (target - b_final) (mod 251)` was solved by calculating the inverse matrix modulo 251. This yielded the byte array `[120, 108, 109, 97, 116, 114, 105, 120]`, which translates to the ASCII password `"xlmatrix"`.
2. **Keystream Generation**: We implemented the custom `s2` keystream generator in Python. It used the recovered password as the initial state for the Feistel-like network to generate the keystream bytes.
3. **QR Decryption**: By XORing the encrypted data from `s3` with the generated keystream, we recovered a 26×80 pixel bitmap. 
4. **Extracting the Flag**: Reading the bitmap revealed two lines of dot-matrix text containing the flag. (Our initial assumption that the password `"xlmatrix"` was the flag was incorrect).

### Solve Script
```python
# decrypt.py / decode_font.py
# Implements the GF(251) matrix inversion and the custom stream cipher.
def cipher(password):
    pw = [ord(c) for c in password]
    B4 = pw[0]+256*pw[1]; C4 = pw[2]+256*pw[3]
    D4 = pw[4]+256*pw[5]; E4 = pw[6]+256*pw[7]
    m = lambda x: x % 65536
    A = 0
    # ... stream cipher logic based on the s2 sheet ...
    # returns keystream array
```

### Flag
`alfa{here_is_your_snack}`

---

## Russian

### Описание задания
**Терминал учёта провизии** — это нестандартное задание по реверс-инжинирингу, реализованное целиком внутри Google-таблицы. Таблица работала как эмулятор терминала, содержала 8 ячеек для ввода пароля и закодированный QR-код ниже. Задача заключалась в том, чтобы отреверсить логику вычислений в таблице, подобрать пароль и расшифровать QR-код, в котором находился флаг.

### Анализ логики и реверс-инжиниринг
Структура документа состояла из нескольких листов:
- **Panel** — Пользовательский интерфейс: 8 ячеек ввода пароля и битмап QR-кода.
- **s1** — Логика проверки пароля. Представляла собой трёхслойную линейную функцию над полем Галуа `GF(251)`:
  - L0 = `M1 = rows40_42 @ P mod 251` (3 значения)
  - L1 = `(W1 @ P + b1) mod 251`
  - L2 = `(W2a @ L1 + W2b @ P + b2) mod 251`
  - L3 = `(W3a @ L2 + W3b @ L1 + ... + b3) mod 251`
  - Целевой вектор `L3` должен был равняться `[92, 97, 27, 240, 199, 80, 217, 23]`.
- **s2** — Генератор гаммы (потоковый шифр на базе сети Фейстеля, по модулю 65536), зависящий от введенного пароля.
- **s3** — Зашифрованные данные QR-кода (26×10 байт).

### Процесс эксплуатации
1. **Восстановление пароля**: Так как вся проверка пароля на листе `s1` состояла из линейных операций над `GF(251)`, мы "свернули" все три слоя в один итоговый линейный оператор `A_final ∈ GF(251)^{8×8}`. Уравнение `A_final @ P ≡ (target - b_final) (mod 251)` было решено через обратную матрицу по модулю 251. Результатом стал массив байт `[120, 108, 109, 97, 116, 114, 105, 120]`, что в ASCII означает пароль `"xlmatrix"`.
2. **Генерация гаммы**: Мы переписали кастомный генератор из листа `s2` на Python. В качестве начального состояния для генерации байтов гаммы (keystream) использовался найденный пароль.
3. **Расшифровка QR-кода**: Сделав XOR зашифрованных данных с листа `s3` с полученной гаммой, мы получили битмап размером 26×80 пикселей.
4. **Получение флага**: Внутри расшифрованного битмапа оказались две строки текста, написанные точечным шрифтом, которые содержали флаг. (Изначальная гипотеза, что пароль `"xlmatrix"` и есть флаг, не подтвердилась).

### Скрипт решения
```python
# decrypt.py / decode_font.py
# Реализует обращение матрицы в GF(251) и кастомный потоковый шифр.
def cipher(password):
    pw = [ord(c) for c in password]
    B4 = pw[0]+256*pw[1]; C4 = pw[2]+256*pw[3]
    D4 = pw[4]+256*pw[5]; E4 = pw[6]+256*pw[7]
    m = lambda x: x % 65536
    A = 0
    # ... логика потокового шифра из листа s2 ...
    # возвращает массив keystream
```

### Флаг
`alfa{here_is_your_snack}`
