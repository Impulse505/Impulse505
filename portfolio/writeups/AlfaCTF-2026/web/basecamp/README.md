# Basecamp (Web/Pwn) — AlfaCTF 2026

## English

### Challenge Description
**Basecamp** was a Go-based web service for managing course access. It used a separate "revocation service" to validate one-time tokens. The goal was to bypass the token validation and gain unauthorized access to the flag.

### Vulnerability Analysis
The vulnerability lied in the **Revocation Service** implemented in Go. It used a mutex to protect access to the token store and an unbuffered channel to communicate the result of a check back to the handler, with a **50ms timeout**.

**The Mutex Deadlock Pattern:**
1. The handler starts a goroutine to check/revoke a token.
2. The goroutine locks the mutex: `s.store.mu.Lock()`.
3. It uses `defer s.store.mu.Unlock()` to ensure the mutex is released.
4. After processing, it sends the result to an unbuffered channel: `ch <- revoked`.
5. **The Bug**: If the main handler times out (50ms) before the goroutine can send the result, the handler returns. The goroutine remains **blocked forever** on `ch <- revoked` because there's no longer a receiver.
6. Since the goroutine is blocked, the `defer` never executes, and the **mutex is never unlocked**.

### Exploitation Process
1. **Saturation**: By sending multiple concurrent requests (e.g., 50+) using different one-time tokens, we can create enough "pressure" on the mutex.
2. **Triggering Deadlock**: If at least one goroutine takes longer than 50ms to acquire the mutex and reach the channel send, it will block forever upon reaching `ch <- revoked` if the handler has already timed out.
3. **Persistent Lock**: Once the mutex is deadlocked, the revocation service becomes unresponsive or fails open, allowing us to retrieve the flag.

### Solve Script (Conceptual)
The exploit uses multi-threading and a barrier to ensure all requests hit the server at the exact same moment to maximize the chance of a race condition/deadlock.

```python
import threading
import requests
import time

URL = "https://basecamp-srv.alfactf.ru/api"

def exploit():
    # 1. Register and get session
    # 2. Generate 60 one-time tokens via /request-access
    # 3. Use 50 threads to hit /api/use-token simultaneously
    barrier = threading.Barrier(50)
    
    def worker(token):
        barrier.wait()
        requests.post(f"{URL}/use-token", json={"token": token})

    # ... launch threads ...
```

### Flag
`alfa{bA5E_sKIll_f0R_gO_1S_D0_no7_4LL0w_F4Il_0P3n}`

---

## Russian

### Описание задания
**Basecamp** — это веб-сервис на Go для управления доступом к курсам. Для проверки одноразовых токенов использовался отдельный "сервис ревокации" (revocation service). Задача заключалась в обходе проверки токенов для получения флага.

### Анализ уязвимости
Уязвимость находилась в **Revocation Service**. Для защиты хранилища токенов использовался мьютекс (`mutex`), а для передачи результата проверки обратно в обработчик — небуферизированный канал с таймаутом в **50 мс**.

**Механика дедлока:**
1. Обработчик запускает горутину для проверки/отзыва токена.
2. Горутина блокирует мьютекс: `s.store.mu.Lock()`.
3. Используется `defer s.store.mu.Unlock()` для разблокировки.
4. После завершения работы горутина пытается отправить результат в канал: `ch <- revoked`.
5. **Ошибка**: Если основной обработчик завершается по таймауту (50 мс) до того, как горутина успеет отправить данные, горутина **блокируется навсегда** на строке `ch <- revoked`, так как получателя больше нет.
6. Поскольку горутина заблокирована, `defer` не срабатывает, и **мьютекс остается заблокированным навсегда**.

### Процесс эксплуатации
1. **Насыщение**: Отправка множества параллельных запросов (около 50) с разными токенами позволяет создать очередь на мьютексе.
2. **Вызов дедлока**: Если хотя бы одна горутина ждет мьютекс дольше 50 мс, она попадет в ситуацию, где обработчик уже ушел по таймауту, и заблокирует мьютекс навсегда при попытке отправки в канал.
3. **Результат**: После дедлока сервис перестает корректно проверять токены или переходит в состояние ошибки, что позволяет получить флаг.

### Флаг
`alfa{bA5E_sKIll_f0R_gO_1S_D0_no7_4LL0w_F4Il_0P3n}`
