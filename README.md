<div align="center">

<img src="src-tauri/icons/128x128.png" width="96" alt="FlowTrust Logo"/>

# FlowTrust

**Professional Windows Security & Forensics Toolkit**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D4?logo=windows)](https://github.com/AlexSeldon1999/FlowTrust)
[![Built with Tauri](https://img.shields.io/badge/Built%20with-Tauri%201.6-FFC131?logo=tauri)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Backend-Rust-CE422B?logo=rust)](https://www.rust-lang.org)
[![Stars](https://img.shields.io/github/stars/AlexSeldon1999/FlowTrust?style=social)](https://github.com/AlexSeldon1999/FlowTrust/stargazers)

*Обнаруживай угрозы. Снимай ограничения. Восстанавливай систему.*  
*Detect threats. Unlock restrictions. Restore your system.*

</div>

---

## О проекте / About

**FlowTrust** — комплексный инструмент безопасности для Windows, написанный на Rust + Tauri. Помогает обнаруживать вирусы, анализировать запущенные процессы, снимать вирусные ограничения и восстанавливать повреждённую систему — всё в одном приложении с современным тёмным интерфейсом.

> FlowTrust is a comprehensive Windows security toolkit built on Rust + Tauri. It detects malware, analyzes running processes, removes virus-imposed restrictions, and restores damaged system settings — all in one sleek dark-themed app.

---

## ✨ Возможности / Features

<table>
<tr>
<td width="50%">

### 🔬 Анализ процессов
- Дерево процессов (родитель → дочерние)
- CPU и RAM в реальном времени + мини-графики
- Статусы: Критичный / Подозрительный / Система / Безопасен
- Проверка цифровой подписи (WinVerifyTrust)
- **Снятие `ProcessBreakOnTermination`** — убирает защиту вирусов от завершения (BSOD)
- Просмотр загруженных DLL по PID

</td>
<td width="50%">

### 🌐 Сеть
- Все активные TCP/UDP соединения с PID-привязкой
- Состояния: ESTABLISHED, LISTEN, CLOSE_WAIT и др.
- Принудительное закрытие TCP-соединений
- Поиск по адресу, порту, имени процесса

</td>
</tr>
<tr>
<td>

### 🚀 Автозагрузка
- Реестр: `Run`, `RunOnce` (HKLM + HKCU + WOW64)
- Winlogon: `Shell`, `Userinit`, `UIHost`
- `AppInit_DLLs` (HKLM + WOW64)
- Планировщик задач (Scheduled Tasks)
- Удаление и редактирование записей

</td>
<td>

### 🔍 Форензика
- Обнаружение угроз: маскировка, подозрительные пути, отсутствие подписи
- Отправка на VirusTotal по SHA-256 одним кликом
- **Карантин**: перемещение файла в `%APPDATA%\FlowTrust\Quarantine\`
- Удаление вредоносных файлов

</td>
</tr>
<tr>
<td>

### 🔓 Разблокировка (25+ ограничений)
Автоматически снимает вирусные ограничения:

| Ограничение | Ключ реестра |
|---|---|
| Диспетчер задач | `DisableTaskMgr` |
| Редактор реестра | `DisableRegistryTools` |
| Командная строка | `DisableCMD` |
| UAC | `EnableLUA` |
| Windows Defender | `DisableAntiSpyware` |
| Брандмауэр | `EnableFirewall` |
| IFEO hijacking | `Debugger` |
| … и ещё 18+ | |

</td>
<td>

### 🛠 Инструменты
- **SFC /scannow** — целостность системных файлов
- **bootrec** — восстановление MBR, VBR, BCD
- **LogonUI** — восстановление экрана входа
- **Сброс ассоциаций файлов** (.exe, .bat, .reg, .lnk, .msi)
- **Восстановление sethc.exe / utilman.exe** (антибэкдор)
- **Сброс Hosts-файла** и прокси-настроек
- **Руткит-детектор**: TlHelp32 + PSAPI + brute-force OpenProcess
- **Встроенный браузер**: VirusTotal, Any.run, Hybrid Analysis

</td>
</tr>
<tr>
<td>

### 📁 Файловый менеджер
- Работает **без explorer.exe** — через Win32 API
- Поддержка скрытых и системных файлов (H/S/R)
- Адресная строка с хлебными крошками
- Панель дисков с индикатором заполнения
- Операции: копировать, переименовать, удалить, создать папку
- Проверка файлов через VirusTotal

</td>
<td>

### ⚙ Настройки
- Поверх всех окон (Always on Top)
- Уведомления об угрозах
- Режим маскировки заголовка окна
- Автообновление списка процессов
- Переключение языка 🇷🇺 RU / 🇬🇧 EN
- Сворачивание в системный трей

</td>
</tr>
</table>

---

## 🔧 Сборка / Build

### Требования / Requirements

| Компонент | Версия |
|---|---|
| [Rust](https://rustup.rs/) | 1.75+ |
| [Node.js](https://nodejs.org/) | 18+ |
| Windows | 10/11 x64 |

### Запуск в режиме разработки / Dev mode
```bash
npm install
npm run tauri dev
```

### Сборка релиза / Production build
```bash
npm run tauri build
```

Артефакты / Artifacts:
```
src-tauri/target/release/bundle/
  msi/FlowTrust_x64_en-US.msi
  nsis/FlowTrust_x64-setup.exe
```

---

## ⚠ Права администратора / Admin rights

Для полного функционала запускай от имени администратора.  
Some features require **Administrator privileges** to work correctly:

- SFC, MBR/BCD repair
- HKLM registry operations
- Windows Defender policies
- Снятие `ProcessBreakOnTermination` у защищённых процессов

---

## 📦 Стек / Tech Stack

| Компонент | Технология |
|---|---|
| Backend | Rust + Tauri 1.6 |
| Frontend | HTML5 / CSS3 / Vanilla JS |
| Win32 API | windows-rs 0.52 |
| NT API | NtSetInformationProcess, NtQueryInformationProcess |
| Хэширование | sha2 0.10 |
| Подписи | WinVerifyTrust (wintrust.dll) |
| Установщик | NSIS / MSI |

---

## 🛡 Отказ от ответственности / Disclaimer

FlowTrust предназначен **исключительно для защитных целей**: диагностики, восстановления системы и обнаружения вредоносного ПО.

> FlowTrust is intended **solely for defensive use**: system diagnostics, recovery, and malware detection. Misuse for unauthorized access is prohibited.

---

## 📬 Контакты / Contacts

- Telegram: [@Jimmy_Hawkins](https://t.me/Jimmy_Hawkins)

---

## 📄 Лицензия / License

[MIT License](LICENSE) — свободное использование с сохранением указания авторства.
