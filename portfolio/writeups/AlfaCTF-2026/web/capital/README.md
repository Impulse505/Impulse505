# capital (Web) — alfaCTF 2026

## English

### Challenge Description
The **capital** challenge was a bank credit scoring system utilizing an ML model on the backend. The objective was to obtain an approval for the "ULTRA-LOW-RISK" credit product. We successfully gained code execution and extracted the model, but did not submit the flag in time.

### Vulnerability Analysis
- **Local File Inclusion (LFI)**: The `application_name` field in the `/api/applications/<id>/document` endpoint was not sanitized, leading to an LFI.
- **Model Extraction**: Using the LFI, it was possible to leak the application source code and subsequently download the complete `joblib` ML model.
- **ML Backdoor**: The training data for the model contained easter-egg names ("Цтфный Альфабанкович") that acted as a backdoor, instantly boosting the score.

### Exploitation Process
1. **LFI Exploitation**: I exploited the LFI vulnerability in `application_name` to read `/proc/self/cwd/app.py`.
2. **Extracting the Model**: After finding the model path (`/srv/karabin/secrets/karabin-ratebook`), I downloaded the `joblib` bundle.
3. **Analyzing the ML Model**: I loaded the model locally and discovered it processed names using a `OneHotEncoder`, revealing the backdoor author names.
4. **Local Optimization**: I used a greedy hill climbing algorithm locally to optimize the rest of the application parameters to exceed the `0.93` approval threshold.
5. **Flag Retrieval**: Sending the optimized application payload yielded the flag. *(Note: Flag was obtained, but not submitted in time).*

### Solve Script
```python
# solve.py
# (Payload implementation to trigger the backdoor in the scoring model)
# ... see full solve.py file for details ...
```

### Flag
`alfa{b4NK_CreDIt_ScoR3_was_5tOlen_4Nd_L0AN_WA5_r3cEIV3d}`

---

## Russian

### Описание задания
Задание **capital** представляло собой банковскую систему скоринга кредитов, использующую ML-модель на бекенде. Целью было получить одобрение на кредитный продукт "ULTRA-LOW-RISK". Мы успешно эксплуатировали уязвимость и извлекли модель, однако не успели сдать флаг вовремя.

### Анализ уязвимости
- **LFI (Local File Inclusion)**: Поле `application_name` в эндпоинте `/api/applications/<id>/document` не валидировалось должным образом, что приводило к LFI.
- **Утечка ML-модели**: Через LFI можно было получить исходный код приложения и скачать `joblib` бандл со скоринговой моделью.
- **Бэкдор в ML (Пасхалки)**: В обучающих данных модели присутствовали "пасхальные" имена ("Цтфный Альфабанкович"), работавшие как бэкдор, мгновенно повышавший скор.

### Процесс эксплуатации
1. **Эксплуатация LFI**: Я проэксплуатировал LFI в параметре `application_name` и прочитал `/proc/self/cwd/app.py`.
2. **Извлечение модели**: Обнаружив путь до модели (`/srv/karabin/secrets/karabin-ratebook`), я выкачал `joblib` бандл.
3. **Анализ ML-модели**: Загрузив модель локально, я выяснил, что для обработки имен применяется `OneHotEncoder`, и обнаружил бэкдорные имена автора.
4. **Локальная оптимизация**: С помощью алгоритма greedy hill climbing я локально подобрал остальные параметры так, чтобы превысить порог одобрения `0.93`.
5. **Получение флага**: Отправка оптимизированной заявки привела к выдаче флага. *(Примечание: Флаг был получен, но сдан после окончания времени).*

### Скрипт решения
```python
# solve.py
# (Реализация отправки полезной нагрузки для активации бэкдора в скоринговой модели)
# ... полная версия в файле solve.py ...
```

### Флаг
`alfa{b4NK_CreDIt_ScoR3_was_5tOlen_4Nd_L0AN_WA5_r3cEIV3d}`
