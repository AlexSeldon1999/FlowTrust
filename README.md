# FlowTrust

**FlowTrust** — профессиональный инструмент безопасности и мониторинга для Windows. Помогает обнаруживать вирусы, снимать ограничения, восстанавливать систему и управлять файлами — всё в одном приложении с современным интерфейсом.

> **Professional Windows security & forensics toolkit** — detect threats, unlock restrictions, restore system integrity and manage files in one sleek dark-themed app.

---

## 🖥 Скриншоты / Screenshots

> _Добавьте скриншоты в папку `assets/` и раскомментируйте строки ниже_
>
> <!-- ![Analysis](assets/screen-analysis.png) -->
> <!-- ![Forensics](assets/screen-forensics.png) -->

---

## ✨ Возможности / Features

### 🔬 Анализ процессов / Process Analysis
- Полный список запущенных процессов с деревом зависимостей (родитель → дочерние)
- CPU и RAM в реальном времени с мини-графиком нагрузки
- Статус: Критичный / Подозрительный / Система / Безопасен
- Проверка цифровой подписи (WinVerifyTrust)
- **Снятие критичности** — убирает флаг `ProcessBreakOnTermination` у вирусов, использующих его для защиты от завершения (иначе BSOD)
- Завершение процессов с контекстным меню
- Просмотр загруженных DLL по PID
- Экспорт списка в JSON

---

### 🌐 Сеть / Network
- Все активные TCP/UDP соединения с PID-привязкой
- Состояния: ESTABLISHED, LISTEN, CLOSE_WAIT и др.
- Принудительное закрытие TCP-соединений
- Поиск по адресу, порту, имени процесса

---

### 🚀 Автозагрузка / Startup Manager
- Реестр: `Run`, `RunOnce` (HKLM + HKCU + WOW64)
- Winlogon: `Shell`, `Userinit`, `UIHost`
- `AppInit_DLLs` (HKLM + WOW64)
- Планировщик задач через PowerShell
- Фильтрация по источнику, поиск
- Удаление и редактирование записей

---

### 🔍 Форензика / Forensics
- Обнаружение угроз: маскировка, подозрительные пути, отсутствие образа, отсутствие подписи
- Уровень риска в % для каждого процесса
- Отправка на VirusTotal (SHA-256) одним кликом
- Карантин: перемещение с переименованием в `.quarantined`
- Удаление вредоносных файлов
- Контекстное меню с быстрыми действиями

---

### 🔓 Разблокировка / Unlock
Автоматическое обнаружение и снятие **23 ограничений**, устанавливаемых вирусами:

| Ограничение | Ключ реестра |
|---|---|
| Диспетчер задач | `DisableTaskMgr` |
| Редактор реестра | `DisableRegistryTools` |
| Командная строка | `DisableCMD` |
| Панель управления | `NoControlPanel` |
| UAC отключён | `EnableLUA` |
| Windows Defender | `DisableAntiSpyware` |
| Защита в реальном времени | `DisableRealtimeMonitoring` |
| Брандмауэр (GPO) | `EnableFirewall` |
| Принудительный прокси | `ProxyEnable` |
| Ремап клавиатуры | `Scancode Map` |
| Shell Winlogon | `Shell` |
| … и ещё 12 |  |

---

### 🛠 Инструменты / Tools
- **SFC /scannow** — проверка целостности системных файлов
- **bootrec** — восстановление MBR, VBR, перестройка BCD
- **Восстановление LogonUI** — экран входа Windows
- **Сброс ассоциаций файлов** (.exe, .bat, .reg, .lnk, .msi)
- **Восстановление sethc.exe / utilman.exe** (антибэкдор)
- **Сброс Hosts-файла** и настроек прокси
- **Восстановление мыши и клавиатуры**
- **Поиск скрытых процессов** (руткит-детектор: TlHelp32 + PSAPI + OpenProcess brute-force)
- **Просмотр DLL** для любого процесса по PID
- **Встроенный браузер** с закладками: VirusTotal, Any.run, Hybrid Analysis

---

### 📁 Файловый менеджер / File Manager
- Работает **без explorer.exe** — напрямую через Win32 API
- Поддержка скрытых и системных файлов (атрибуты H/S/R)
- Адресная строка с хлебными крошками
- Панель дисков с индикатором заполнения
- Операции: копировать, вставить, переименовать, удалить, создать папку
- Контекстное меню с проверкой через VirusTotal
- Поиск по имени файла

---

### ⚙ Настройки / Settings
- Поверх всех окон
- Уведомления о новых угрозах
- Режим маскировки заголовка окна (обход мониторинга)
- Переключение языка RU / EN
- Проверка обновлений

---

## 🔧 Сборка / Build

### Требования / Requirements
- [Rust](https://rustup.rs/) 1.75+
- [Node.js](https://nodejs.org/) 18+
- Windows 10/11 (x64)

### Запуск в режиме разработки / Dev mode
```bash
npm install
npm run tauri dev
```

### Сборка релиза / Production build
```bash
npm run tauri build
```

Артефакты появятся в:
```
src-tauri/target/release/bundle/
  msi/FlowTrust_x64_en-US.msi
  nsis/FlowTrust_x64-setup.exe
```

---

## ⚠ Права / Permissions

Некоторые функции (SFC, MBR, Winlogon, реестр HKLM, Defender) требуют **запуска от имени администратора**.

> Some features (SFC, MBR repair, HKLM registry, Defender policies) require **Administrator privileges**.

---

## 🛡 Отказ от ответственности / Disclaimer

FlowTrust предназначен **исключительно для защитных целей**: диагностики, восстановления системы и обнаружения вредоносного ПО. Использование функций (например, `set_accessibility_backdoor`) в нелегитимных целях запрещено.

> FlowTrust is intended **solely for defensive use**: system diagnostics, recovery, and malware detection. Misuse of any functionality for unauthorized access is prohibited.

---

## 📦 Технологии / Tech Stack

| Компонент | Технология |
|---|---|
| Backend | Rust + Tauri 1.6 |
| Frontend | HTML5 / CSS3 / Vanilla JS |
| Win32 API | windows-rs 0.52 |
| Хэширование | sha2 0.10 |
| Упаковщик | NSIS / MSI |

---

## 📬 Контакты / Contacts

- Telegram: [@Jimmy_Hawkins](https://t.me/Jimmy_Hawkins)

---

## 📄 Лицензия / License

MIT License — свободное использование с сохранением указания авторства.

> MIT License — free to use with attribution.
