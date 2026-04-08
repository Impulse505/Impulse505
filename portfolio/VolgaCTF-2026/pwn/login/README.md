# Login (Pwn) — VolgaCTF 2026

## English

### Challenge Description
This was a 32-bit Linux binary that featured a stack buffer overflow. However, the system it was running on was 64-bit, and the exploit required pivoting the stack and transitioning the execution mode from 32-bit to 64-bit to perform a Sigreturn Oriented Programming (SROP) attack.

### Vulnerability Analysis
1.  **Stack Buffer Overflow**: The application reads user input into a small buffer without proper bounds checking, allowing for a standard overflow.
2.  **32-to-64 Bit Transition**: The binary contains an `iret` (interrupt return) instruction and gadgets that allow switching the `CS` (Code Segment) register from `0x23` (32-bit) to `0x33` (64-bit).
3.  **SROP**: Once in 64-bit mode, I could craft a `SigreturnFrame` to trigger a `sys_execve` syscall and spawn a shell.

### Exploitation Strategy
1.  **Stage 1: Stack Pivot**: Overwrite the return address to pivot the stack to a known location (`0x401100`) and read a second, larger payload.
2.  **Stage 2: Mode Switching**:
    -   Use `pop esi; edi; ret` and `read_stdin` to place the SROP frame and `/bin/sh` string into memory.
    -   Use `iret` to switch the CPU to 64-bit mode by setting `CS=0x33`.
3.  **Stage 3: SROP**: Trigger the `sigreturn` syscall (rax=15 in 32-bit, but here I use the 64-bit `rax=59` for `execve` inside the frame) to execute `/bin/sh`.

### Flag
`VolgaCTF{48406e1bf06999724172a17543f9e1d829a83144343d0681871e45489d35b902}`

---

## Russian

### Описание задания
Это 32-битный бинарный файл под Linux, содержащий переполнение буфера в стеке. Особенность заключалась в том, что целевая система была 64-битной, и для успешной эксплуатации требовалось переключить режим выполнения процессора из 32-битного в 64-битный и провести SROP (Sigreturn Oriented Programming) атаку.

### Анализ уязвимости
1.  **Переполнение стека**: Приложение считывает ввод в буфер фиксированного размера без проверки границ.
2.  **Переход 32 -> 64 бит**: Бинарник содержит инструкцию `iret` и гаджеты, позволяющие изменить сегмент кода (`CS`) с `0x23` (32-бит) на `0x33` (64-бит).
3.  **SROP**: В 64-битном режиме можно сформировать `SigreturnFrame` для вызова `sys_execve` и получения оболочки (shell).

### Стратегия эксплуатации
1.  **Этап 1: Stack Pivot**: Перезаписываем адрес возврата, чтобы перенести стек в заранее известную область (`0x401100`) и считать вторую, более объемную часть эксплойта.
2.  **Этап 2: Переключение режима**:
    -   Используем гаджеты для чтения `SigreturnFrame` и строки `/bin/sh` в память.
    -   Вызываем `iret` для перехода процессора в 64-битный режим (установка `CS=0x33`).
3.  **Этап 3: SROP**: Инициируем механизм SROP для выполнения системного вызова `execve("/bin/sh", 0, 0)`.

### Флаг
`VolgaCTF{48406e1bf06999724172a17543f9e1d829a83144343d0681871e45489d35b902}`
