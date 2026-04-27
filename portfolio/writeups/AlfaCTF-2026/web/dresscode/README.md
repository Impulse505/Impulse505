# Dress Code (Web/Crypto) — alfaCTF 2026

## English

### Challenge Description
**Dress Code** was a hard-level Web/Crypto challenge. We were provided with the source code (`tar.gz`) containing a `docker-compose.yml` with MySQL, an initialization service, a Flask-based `shop`, and a Rust-based `validator`. 
The goal was to acquire a complete 8-piece outfit for the "owner" user (`id=1000001`), which cost 703 credits, despite starting with only 100 credits. 

### Vulnerability Analysis
The challenge had a chain of vulnerabilities:
1. **SQL Injection**: The `update_comment` endpoint concatenated `new_comment` into an `UPDATE` query without escaping, allowing arbitrary modification of transaction fields, including the `iv` (Initialization Vector) column.
2. **AES-CBC IV Malleability & MAC Flaw**: The shop encrypted transaction JSONs using AES-256-CBC and computed an HMAC-SHA256 signature **only over the ciphertext**, excluding the IV. Because AES-CBC XORs the IV with the decrypted first block of ciphertext to produce the plaintext, modifying the IV allows direct bit-flipping of the first plaintext block.
3. **Business Logic Flaw**: The Rust validator contained a special condition: if the sender (`from`) was exactly `"1000001"`, it skipped deducting the balance but still deposited the items into the recipient's inventory.

### Exploitation Process
The goal was to spoof the `from` field in the encrypted JSON to `"1000001"`. The JSON payload started with `{"from": "<user_id>"...`.
1. **Account Generation**: Because we could only manipulate the first 16-byte block via IV bit-flipping, the 7th digit of the user ID fell into the second block, which we couldn't manipulate without breaking the ciphertext. We bypassed this by repeatedly registering accounts until we got a `user_id` ending with `1`.
2. **Initiating the Purchase**: We added all 8 required items to the cart and checked out, generating a valid encrypted transaction and MAC.
3. **IV Bit-Flipping via SQLi**: Before the asynchronous validator picked up the transaction (a ~3-second window), we exploited the SQL injection to update the `iv` in the database. We XORed the original IV with the difference between our user ID's first 6 digits and `"100000"`.
4. **Validation and Flag**: The validator decrypted the transaction using the modified IV, resulting in `from="1000001"`. It bypassed the balance check, deposited the items, and hitting the `/check_dresscode` endpoint yielded the flag.

### Flag
`alfa{5mO7rYA_KAK01_fAbRic_5MoTRy4_5k0LkO_D3TAIl5}`

---

## Russian

### Описание задания
**Дресс-код** — это задание категории Web/Crypto (Hard). Был предоставлен архив с исходными кодами: `docker-compose.yml` с базой MySQL, `shop` на Flask и `validator` на Rust.
Цель состояла в том, чтобы собрать полный аутфит из 8 вещей для владельца магазина (`id=1000001`). Вещи стоили 703 кредита, в то время как на балансе было только 100.

### Анализ уязвимости
В приложении присутствовала цепочка уязвимостей:
1. **SQL-инъекция**: Эндпоинт `update_comment` подставлял пользовательский ввод напрямую в запрос `UPDATE` без экранирования. Это позволяло изменять любые поля в таблице `transactions`, включая колонку `iv` (Initialization Vector).
2. **AES-CBC IV Malleability и недостаток MAC**: Магазин шифровал транзакции алгоритмом AES-256-CBC, но HMAC-SHA256 подпись вычислялась **только для шифротекста**, исключая IV. В режиме CBC вектор инициализации XOR-ится с расшифрованным первым блоком, поэтому изменение IV позволяет напрямую манипулировать (bit-flipping) первыми 16 байтами открытого текста.
3. **Уязвимость бизнес-логики**: В валидаторе на Rust было условие: если отправитель (`from`) равен `"1000001"`, списание баланса игнорировалось, но вещи все равно добавлялись в инвентарь получателя.

### Процесс эксплуатации
Цель заключалась в подмене поля `from` в зашифрованном JSON на `"1000001"`. Структура JSON начиналась так: `{"from": "<user_id>"...`.
1. **Генерация аккаунта**: Поскольку через IV можно было изменить только первый 16-байтный блок, седьмая цифра `user_id` попадала во второй блок, который нельзя было изменить без повреждения шифротекста. Для обхода этого мы автоматизировали регистрацию, пока не получали `user_id`, оканчивающийся на `1`.
2. **Создание транзакции**: Мы добавляли 8 целевых предметов в корзину и оформляли заказ, генерируя валидную транзакцию и подпись (MAC).
3. **Bit-Flipping IV через SQLi**: До того как асинхронный валидатор успевал обработать транзакцию (окно около 3 секунд), мы использовали SQL-инъекцию для обновления `iv` в базе данных. Оригинальный IV "ксорился" с разницей между первыми 6 цифрами нашего ID и `"100000"`.
4. **Валидация и получение флага**: Валидатор расшифровывал транзакцию с новым IV и получал `from="1000001"`. Проверка баланса успешно обходилась, вещи зачислялись в инвентарь, и запрос к `/check_dresscode` отдавал флаг.

### Флаг
`alfa{5mO7rYA_KAK01_fAbRic_5MoTRy4_5k0LkO_D3TAIl5}`
