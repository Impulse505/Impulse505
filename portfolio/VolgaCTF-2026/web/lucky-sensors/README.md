# LuckySensors (Web) — VolgaCTF 2026

## English

### Challenge Description
The **LuckySensors** web challenge was a data-monitoring application that presented sensor readings. The application was vulnerable to **Blind Boolean-Based SQL Injection** via the `sortField` parameter in a search endpoint.

### Vulnerability Analysis
The `sortField` parameter was directly concatenated into the SQL `ORDER BY` clause. By using a `CASE` statement, I could perform operations based on whether a condition was true or false:
`CASE WHEN (CONDITION) THEN id ELSE sensorValue END`

This would change the sort order of the results, allowing me to infer the outcome of the boolean condition.

### Exploitation Step-by-Step
1.  **Detecting the Injection**: I identified the `sortField` vulnerability by observing how the response changed when providing different column names or expressions.
2.  **Developing an Exploit**: I wrote a Node.js script to automate the data extraction. The script used a binary search algorithm to speed up the process of extracting characters from the database.
3.  **Data Extraction**: I successfully extracted sensitive table information and ultimately retrieved the flag from the database.

### Solve Script

```javascript
// solve.js
const http = require('http');
// ... Node.js script for blind SQL injection using CASE in ORDER BY ...
async function checkCondition(condition) {
    const sortField = `(CASE WHEN (${condition}) THEN value ELSE -value END)`;
    const url = `http://lucky-sensor-1.q.2026.volgactf.ru:8000/api/sensors/1/readings?sortField=${encodeURIComponent(sortField)}&sortDirection=ASC`;
    // ...
}
```


### Flag
`VolgaCTF{cl1ck_un10n_4_d4t4_3xf1l}
` 

---

## Russian

### Описание задания
Веб-задание **LuckySensors** — это мониторинговое приложение для отображения показаний датчиков. Приложение было уязвимо к **Blind Boolean-Based SQL Injection** (слепой логической SQL-инъекции) через параметр `sortField` в эндпоинте поиска.

### Анализ уязвимости
Параметр `sortField` напрямую вставлялся в SQL-запрос в секцию `ORDER BY`. С помощью оператора `CASE` мне удалось реализовать логику ветвления:
`CASE WHEN (CONDITION) THEN id ELSE sensorValue END`

Это приводило к изменению порядка сортировки результатов в ответе, что позволяло судить об истинности или ложности проверяемого условия.

### Процесс эксплуатации
1.  **Нахождение инъекции**: Я подтвердил наличие уязвимости в `sortField`, заметив изменение порядка строк в ответе при отправке различных выражений.
2.  **Написание эксплойта**: Я разработал Node.js скрипт для автоматизации извлечения данных. Скрипт использовал алгоритм бинарного поиска для ускоренного получения символов из базы данных.
3.  **Извлечение данных**: Мне удалось вытянуть структуру таблиц и, в конечном итоге, сам флаг.

### Скрипт решения

```javascript
// solve.js
// (Реализация слепой SQL-инъекции через CASE в ORDER BY)
// ... аналогично версии на английском ...
```


### Флаг
`VolgaCTF{cl1ck_un10n_4_d4t4_3xf1l}
` 
