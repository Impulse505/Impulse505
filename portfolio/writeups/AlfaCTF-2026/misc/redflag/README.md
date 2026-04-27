# Redflag (Misc) — AlfaCTF 2026

## English

### Challenge Description
**Redflag** was a terminal-based (TUI) application accessed via SSH. It allowed users to create, join, and manage "tier-lists". The goal was to exploit the directory management logic to access a locked flag.

### Vulnerability Analysis
The application was driven by a shell script (`redflag.sh`) that managed directories for each tier-list.

**Path Confusion in Suffix Removal:**
When a user "leaves" a tier-list, the script attempts to move or rename the user's directory. It uses a bash suffix removal pattern to derive the tier-list's base name from its directory name:
```bash
base_name="${dir_name%__with__${CURRENT_USER}}"
```
**The Bug**: If a user creates a tier-list with a name specifically crafted to contain `__with__` multiple times or in an unexpected way, the suffix removal logic might return an incorrect path. This can be exploited to trick the script into operating on directories outside the user's intended scope.

### Exploitation Process
1. **Connect** via SSH: `ssh -p 2222 user@redflag.alfactf.ru`.
2. **Create a Malicious Tier-list**: Create a tier-list named something like `gorpcore_redflags__with__impulsex`.
3. **Manipulate Path**: By joining and leaving specific tier-lists, we can trigger the renaming logic to "uncover" or move the restricted `flag` directory into a state where it's readable or its contents are revealed in the TUI menu.
4. **Retrieve Flag**: The flag appears in the TUI list once the directory structure is manipulated.

### Solve Script
The provided `exploit.py` uses the `pexpect` library to automate the SSH TUI interaction.

### Flag
`alfa{mv_from_W3b_U1_T0_Wh1Pta1L}`

---

## Russian

### Описание задания
**Redflag** — консольное приложение (TUI), доступное через SSH. Оно позволяло пользователям создавать, вступать и управлять "тир-листами". Задача — обойти логику управления директориями и получить доступ к заблокированному флагу.

### Анализ уязвимости
Приложение управлялось шелл-скриптом (`redflag.sh`), который создавал и переименовывал папки для каждого тир-листа.

**Путаница путей при удалении суффикса:**
Когда пользователь покидает тир-лист, скрипт пытается определить базовое имя тир-листа, отсекая суффикс с именем пользователя:
```bash
base_name="${dir_name%__with__${CURRENT_USER}}"
```
**Ошибка**: Если создать тир-лист с именем, содержащим `__with__` определенным образом, логика удаления суффикса в Bash может сработать некорректно, вернув неожиданный путь. Это позволяет манипулировать операциями переименования (`mv`) и перемещать директории, к которым у пользователя не должно быть прямого доступа.

### Процесс эксплуатации
1. **Подключение** по SSH.
2. **Создание тир-листа** со специально подобранным именем (например, `gorpcore_redflags__with__impulsex`).
3. **Манипуляция путями**: Вступая и выходя из тир-листов, мы заставляем скрипт переместить папку с флагом или изменить её статус так, что она становится доступной для чтения в меню TUI.
4. **Получение флага**: Флаг отображается в списке элементов тир-листа после успешной манипуляции.

### Скрипт решения
Приложенный файл `exploit.py` автоматизирует взаимодействие с SSH TUI с помощью библиотеки `pexpect`.

### Флаг
`alfa{mv_from_W3b_U1_T0_Wh1Pta1L}`
