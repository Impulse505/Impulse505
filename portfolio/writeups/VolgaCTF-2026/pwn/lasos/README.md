# lasOS (Kernel Pwn) — VolgaCTF 2026

## English

### Challenge Description
The **lasOS** challenge was a kernel-side pwnable task. I was provided with a custom kernel image (`image.bin`) and a script to run it in QEMU. The goal was to exploit a vulnerability in a custom syscall implemented in the OS.

### Vulnerability Analysis
- **Custom Syscall**: The OS implemented a few custom syscalls. By re-implementing the syscall interface, I discovered a memory corruption vulnerability (likely a buffer overflow) in the handling of user-supplied data within a specific syscall.
- **Kernel Space**: The vulnerability allowed for arbitrary code execution in kernel mode.

### Exploitation Path
1.  **Reversed-engineering the Kernel**: I disassembled the kernel binary and identified the custom syscall handler.
2.  **Developing the Payload**: Since the OS was minimalist, I used a stack-based exploit to redirect execution. I crafted a payload that would read the flag file directly from the filesystem or memory within kernel space.
3.  **Bypassing Protections**: Given the custom nature of the OS, standard kernel protections were absent, making reliable exploitation possible once the offset was identified.

### Exploit Script

```python
# exploit.py 
# (Simplistic kernel shellcode to leak the flag via I/O port)
import struct
import socket

def exploit(target_ip, target_port):
    shellcode = b"\xfa" # cli ...
    # (Payload logic to scan memory and outb)
    rip_overwrite = struct.pack("<Q", 0xffffff8000005fc0)
    payload = b"100 " + shellcode + b"A" * (0x48 - len(shellcode)) + rip_overwrite
    # ...
```


### Flag
`VolgaCTF{k3rn3l_pwn_1s_n0t_that_hard_r1ght?}` 

---

## Russian

### Описание задания
Задание **lasOS** — это пример kernel-pwn. Был предоставлен кастомный образ ядра (`image.bin`) и скрипт для запуска в QEMU. Задача заключалась в эксплуатации уязвимости в одном из кастомных системных вызовов (syscall), реализованных в этой ОС.

### Анализ уязвимости
- **Кастомный Syscall**: В ОС было реализовано несколько специфических системных вызовов. При изучении интерфейса syscall'ов была обнаружена возможность повреждения памяти (вероятно, переполнение буфера) при обработке данных пользователя.
- **Ядро**: Уязвимость позволяла выполнять произвольный код в привилегированном режиме ядра.

### Процесс эксплуатации
1.  **Реверс-инжиниринг**: Я дизассемблировал бинарный файл ядра и нашел обработчики системных вызовов.
2.  **Разработка пейлоада**: Поскольку ОС была минималистичной, я использовал переполнение стека для перехвата управления. Пейлоад считывал файл флага напрямую из файловой системы или памяти ядра.
3.  **Обход защит**: В силу того, что это была учебная/кастомная ОС, современные средства защиты ядра отсутствовали, что позволило добиться стабильной эксплуатации после нахождения нужного смещения.

### Скрипт эксплоита

```python
# exploit.py
# (Использование переполнения буфера в syscall и выполнение kernel shellcode)
# ... аналогично версии на английском ...
```


### Флаг
`VolgaCTF{k3rn3l_pwn_1s_n0t_that_hard_r1ght?}` 
