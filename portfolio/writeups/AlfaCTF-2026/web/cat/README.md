# cat (Web) — alfaCTF 2026

## English

### Challenge Description
The **cat** web challenge was a client-side Three.js runner game. The goal was to reach 100% completion by exploiting the cheat codes interface. The interface had client-side DOM and CSS protections that needed to be bypassed.

### Vulnerability Analysis
- **Client-Side Protection**: The protection for reading cheat codes was entirely client-side. The cheat codes canvas was obscured using a CSS `blur(9px)` filter and a `.cheat-cover` DOM element.
- **Cheat Codes Exposure**: Once the visual protections were removed, the cheat codes "catcatcat" (faster) and "powerup" (god mode) were visible and could be typed directly into the game.

### Exploitation Process
1. **Removing Protections**: I opened the browser's DevTools console and removed the CSS blur filter and hid the overlay element.
2. **Extracting Codes**: I read the cheat codes from the exposed canvas.
3. **Winning the Game**: I activated the "catcatcat" and "powerup" cheats during gameplay, achieving 100% completion and revealing the flag.

### Solve Script
```javascript
// solve.js
// Execute this in the browser console
document.querySelector('.cheat-copy-canvas').style.filter = 'none';
document.querySelector('.cheat-cover').style.display = 'none';
```

### Flag
`alfa{music_cat_in_a_backpack}`

---

## Russian

### Описание задания
Веб-задание **cat** представляло собой раннер на Three.js. Задача заключалась в прохождении игры на 100% за счет использования чит-кодов. Интерфейс с чит-кодами был защищен клиентскими DOM и CSS механизмами, которые требовалось обойти.

### Анализ уязвимости
- **Клиентская защита**: Механизм сокрытия чит-кодов находился полностью на клиенте. Текст с кодами был скрыт при помощи CSS-фильтра `blur(9px)` и перекрывающего DOM-элемента `.cheat-cover`.
- **Утечка чит-кодов**: После снятия визуальной защиты, коды "catcatcat" (ускорение) и "powerup" (бессмертие) становились видимыми на canvas и их можно было ввести в игре.

### Процесс эксплуатации
1. **Снятие защиты**: Я открыл консоль DevTools и убрал CSS-размытие, а также скрыл перекрывающий элемент.
2. **Получение кодов**: Я считал открывшиеся чит-коды с canvas.
3. **Прохождение игры**: Во время игры я ввел коды "catcatcat" и "powerup", что позволило мне набрать 100% и получить флаг.

### Скрипт решения
```javascript
// solve.js
// Выполнить в консоли браузера
document.querySelector('.cheat-copy-canvas').style.filter = 'none';
document.querySelector('.cheat-cover').style.display = 'none';
```

### Флаг
`alfa{music_cat_in_a_backpack}`
