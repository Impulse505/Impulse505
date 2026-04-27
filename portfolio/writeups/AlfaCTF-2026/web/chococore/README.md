# chococore (Web) — alfaCTF 2026

## English

### Challenge Description
The **chococore** web challenge was an online chocolate store. The goal was to purchase a "flag" chocolate that cost 31,337 credits, while the starting balance was insufficient. 

### Vulnerability Analysis
- **Type Coercion / Logic Flaw**: The `/api/promocode` endpoint decoded promocodes from base64 JSON and processed the `amount` field. The backend logic immediately added the amount to the balance, then validated the type. If the type was not a number (e.g., a string), it threw an error and subtracted the amount in a `catch` block before saving in `finally`.
- **Exploitation**: In JavaScript, adding a string to a number concatenates them (e.g., `5000 + "31337"` becomes `"500031337"`). However, subtracting a string from a string forces numerical subtraction (e.g., `"500031337" - "31337"` equals `500000000`). This results in a massive artificial balance increase.

### Exploitation Process
1. **Session Setup**: I initiated a session to get a valid `session_id`.
2. **Valid Promocode**: I applied a valid promocode to ensure the balance was greater than zero.
3. **Malicious Promocode**: I crafted a malicious JSON payload with the `amount` as a string (`"31337"`). The server concatenated it and then subtracted it numerically, leaving the account with an enormous balance.
4. **Flag Retrieval**: With sufficient funds, I added the flag chocolate to the cart, checked out, and completed the order to receive the flag.

### Solve Script
```python
# solve.py
# (Payload script to exploit the JS type coercion and retrieve the flag)
# ... see full solve.py file for details ...
```

### Flag
`alfa{5hu7_UP_4nd_SELl_Me_moRE_tH35E_CH0C0l47E5}`

---

## Russian

### Описание задания
Веб-задание **chococore** представляло собой магазин шоколада. Задача заключалась в покупке "флага" стоимостью 31 337 кредитов, хотя начальный баланс был недостаточен.

### Анализ уязвимости
- **Type Coercion (Приведение типов) / Ошибка логики**: Эндпоинт `/api/promocode` декодировал промокоды из base64 JSON. Логика бекенда сначала прибавляла `amount` к балансу, затем проверяла тип. Если тип не был числом (например, строка), возникала ошибка, и в блоке `catch` значение вычиталось обратно перед сохранением в `finally`.
- **Эксплуатация**: В JavaScript при сложении числа и строки происходит конкатенация (`5000 + "31337"` → `"500031337"`). Но при вычитании происходит математическое действие (`"500031337" - "31337"` → `500000000`). Это позволило искусственно увеличить баланс.

### Процесс эксплуатации
1. **Настройка сессии**: Я запросил новую сессию для получения `session_id`.
2. **Валидный промокод**: Я активировал обычный промокод, чтобы сделать баланс больше нуля.
3. **Вредоносный промокод**: Я создал вредоносный JSON, где `amount` передавался как строка (`"31337"`). Сервер выполнил конкатенацию, затем вычитание, оставив на счету огромный баланс.
4. **Получение флага**: Обладая достаточными средствами, я добавил флаг в корзину, оформил заказ и получил заветную строку.

### Скрипт решения
```python
# solve.py
# (Полезная нагрузка для эксплуатации приведения типов JS и покупки флага)
# ... полная версия в файле solve.py ...
```

### Флаг
`alfa{5hu7_UP_4nd_SELl_Me_moRE_tH35E_CH0C0l47E5}`
