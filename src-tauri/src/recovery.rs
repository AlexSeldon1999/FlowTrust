// Модуль восстановления системы и разблокировки ограничений

use std::process::Command as SysCmd;
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegEnumValueW, RegOpenKeyExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ, KEY_WRITE,
    REG_DWORD, REG_SZ, REG_VALUE_TYPE,
};
use windows::core::PCWSTR;

// ── Хелпер: строка → HKEY ─────────────────────────────────────────────────────

fn hive(s: &str) -> HKEY {
    if s.eq_ignore_ascii_case("hklm") { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Реестр: примитивы ─────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

/// Проверить, существует ли значение в ключе реестра.
pub fn reg_value_exists(hive_str: &str, key: &str, value_name: &str) -> bool {
    unsafe {
        let wide_key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(hive(hive_str), PCWSTR(wide_key.as_ptr()), 0, KEY_READ, &mut hkey).is_err() {
            return false;
        }
        let target = value_name.to_lowercase();
        let mut index = 0u32;
        let mut found = false;
        loop {
            let mut name_buf = vec![0u16; MAX_PATH as usize];
            let mut name_len = MAX_PATH;
            if RegEnumValueW(
                hkey, index,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None, None, None, None,
            ).is_err() { break; }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]).to_lowercase();
            if name == target { found = true; break; }
            index += 1;
        }
        let _ = RegCloseKey(hkey);
        found
    }
}

/// Прочитать DWORD значение. Возвращает -1 если отсутствует.
pub fn reg_read_dword(hive_str: &str, key: &str, value_name: &str) -> i64 {
    unsafe {
        let wide_key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(hive(hive_str), PCWSTR(wide_key.as_ptr()), 0, KEY_READ, &mut hkey).is_err() {
            return -1;
        }
        let target = value_name.to_lowercase();
        let mut index = 0u32;
        let mut result = -1i64;
        loop {
            let mut name_buf = vec![0u16; MAX_PATH as usize];
            let mut name_len = MAX_PATH;
            let mut data_buf = [0u8; 8];
            let mut data_len = 8u32;
            let mut vtype = 0u32;
            if RegEnumValueW(
                hkey, index,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut vtype),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            ).is_err() { break; }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]).to_lowercase();
            if name == target && vtype == REG_DWORD.0 && data_len >= 4 {
                result = u32::from_le_bytes([data_buf[0], data_buf[1], data_buf[2], data_buf[3]]) as i64;
                break;
            }
            index += 1;
        }
        let _ = RegCloseKey(hkey);
        result
    }
}

/// Удалить значение из реестра (снятие ограничения).
pub fn reg_delete_value(hive_str: &str, key: &str, value_name: &str) -> Result<(), String> {
    unsafe {
        let wide_key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(hive(hive_str), PCWSTR(wide_key.as_ptr()), 0, KEY_WRITE, &mut hkey).is_err() {
            // Ключ не существует — ограничение уже снято
            return Ok(());
        }
        let wide_val: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();
        let err = RegDeleteValueW(hkey, PCWSTR(wide_val.as_ptr()));
        let _ = RegCloseKey(hkey);
        if err.is_err() { Err(format!("{:?}", err)) } else { Ok(()) }
    }
}

/// Записать DWORD значение в реестр.
pub fn reg_set_dword(hive_str: &str, key: &str, value_name: &str, data: u32) -> Result<(), String> {
    unsafe {
        let wide_key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
        let mut hkey = HKEY::default();
        RegOpenKeyExW(hive(hive_str), PCWSTR(wide_key.as_ptr()), 0, KEY_WRITE, &mut hkey)
            .map_err(|e| format!("Ключ не найден: {e}"))?;
        let wide_val: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();
        let bytes: [u8; 4] = data.to_le_bytes();
        let err = RegSetValueExW(
            hkey,
            PCWSTR(wide_val.as_ptr()),
            0,
            REG_VALUE_TYPE(REG_DWORD.0),
            Some(&bytes),
        );
        let _ = RegCloseKey(hkey);
        if err.is_err() { Err(format!("{:?}", err)) } else { Ok(()) }
    }
}

/// Записать строковое значение (REG_SZ) в реестр.
pub fn reg_set_string(hive_str: &str, key: &str, value_name: &str, data: &str) -> Result<(), String> {
    unsafe {
        let wide_key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
        let mut hkey = HKEY::default();
        RegOpenKeyExW(hive(hive_str), PCWSTR(wide_key.as_ptr()), 0, KEY_WRITE, &mut hkey)
            .map_err(|e| format!("Ключ не найден: {e}"))?;
        let wide_val: Vec<u16>  = value_name.encode_utf16().chain(Some(0)).collect();
        let wide_data: Vec<u16> = data.encode_utf16().chain(Some(0)).collect();
        let bytes = std::slice::from_raw_parts(
            wide_data.as_ptr() as *const u8,
            wide_data.len() * 2,
        );
        let err = RegSetValueExW(
            hkey,
            PCWSTR(wide_val.as_ptr()),
            0,
            REG_VALUE_TYPE(REG_SZ.0),
            Some(bytes),
        );
        let _ = RegCloseKey(hkey);
        if err.is_err() { Err(format!("{:?}", err)) } else { Ok(()) }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Выполнение команд ─────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

/// Запустить команду и стримить вывод построчно через callback.
/// Объединяет stderr в stdout через `2>&1`.
/// Используется для интерактивного терминала в UI.
pub fn run_cmd_stream<F>(cmd: &str, powershell: bool, mut on_line: F)
where
    F: FnMut(String) + Send + 'static,
{
    use std::io::{BufRead, BufReader};
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    // Используем полные пути — в Tauri-окружении PATH может быть урезан
    let shell = if powershell {
        let sysroot = std::env::var("SystemRoot")
            .unwrap_or_else(|_| r"C:\Windows".to_string());
        format!(r"{}\System32\WindowsPowerShell\v1.0\powershell.exe", sysroot)
    } else {
        std::env::var("COMSPEC")
            .unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_string())
    };

    let ps_cmd = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ErrorActionPreference='Continue'; {} 2>&1",
        cmd
    );

    let mut builder = if powershell {
        let mut b = SysCmd::new(&shell);
        b.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd]);
        b
    } else {
        let mut b = SysCmd::new(&shell);
        b.args(["/u", "/c", &format!("{} 2>&1", cmd)]);
        b
    };

    builder
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());

    #[cfg(windows)]
    builder.creation_flags(0x08000000); // CREATE_NO_WINDOW

    match builder.spawn() {
        Ok(mut ch) => {
            if let Some(stdout) = ch.stdout.take() {
                // CMD /U outputs UTF-16LE; PowerShell outputs UTF-8
                if powershell {
                    for line in BufReader::new(stdout).lines() {
                        match line {
                            Ok(l) => on_line(l),
                            Err(_) => break,
                        }
                    }
                } else {
                    // CMD /U: читаем попарно байты как UTF-16LE
                    use std::io::Read;
                    let mut raw = Vec::new();
                    let _ = BufReader::new(stdout).read_to_end(&mut raw);
                    // Decode UTF-16LE
                    let u16s: Vec<u16> = raw.chunks_exact(2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .collect();
                    let text = String::from_utf16_lossy(&u16s);
                    for line in text.lines() {
                        on_line(line.to_string());
                    }
                }
            }
            let _ = ch.wait();
        }
        Err(e) => on_line(format!("[ОШИБКА] Не удалось запустить {}: {}", if powershell { "PowerShell" } else { "CMD" }, e)),
    }
}

/// Выполнить команду через CMD или PowerShell и вернуть вывод.
pub fn run_cmd(cmd: &str, powershell: bool) -> String {
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    let shell = if powershell {
        let sysroot = std::env::var("SystemRoot")
            .unwrap_or_else(|_| r"C:\Windows".to_string());
        format!(r"{}\System32\WindowsPowerShell\v1.0\powershell.exe", sysroot)
    } else {
        std::env::var("COMSPEC")
            .unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_string())
    };

    let mut builder = if powershell {
        let mut b = SysCmd::new(&shell);
        b.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                &format!("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; {}", cmd)]);
        b
    } else {
        let mut b = SysCmd::new(&shell);
        b.args(["/u", "/c", cmd]); // /u → UTF-16LE output (avoids OEM/CP866 garbage)
        b
    };
    #[cfg(windows)]
    builder.creation_flags(0x08000000);

    let result = builder.output();
    match result {
        Ok(out) => {
            let stdout = if powershell {
                String::from_utf8_lossy(&out.stdout).to_string()
            } else {
                // CMD /u outputs UTF-16LE — decode properly
                let u16s: Vec<u16> = out.stdout.chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s).to_string()
            };
            let stderr = if powershell {
                String::from_utf8_lossy(&out.stderr).to_string()
            } else {
                let u16s: Vec<u16> = out.stderr.chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s).to_string()
            };
            let mut text = stdout;
            if !stderr.is_empty() { text.push_str(&format!("\n[ERR] {}", stderr.trim())); }
            if text.trim().is_empty() {
                format!("[Exit: {}]", out.status.code().unwrap_or(0))
            } else { text }
        }
        Err(e) => format!("[ERROR] {}", e),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Функции восстановления системы ───────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

/// SFC /scannow — проверка целостности системных файлов (требует администратора)
pub fn run_sfc() -> String {
    run_cmd("sfc /scannow", false)
}

/// Восстановление загрузочной записи MBR/VBR (требует администратора)
pub fn fix_mbr() -> String {
    let mut out = String::new();
    out.push_str("=== bootrec /fixmbr ===\n");
    out.push_str(&run_cmd("bootrec /fixmbr", false));
    out.push_str("\n=== bootrec /fixboot ===\n");
    out.push_str(&run_cmd("bootrec /fixboot", false));
    out
}

/// Перестройка BCD (Boot Configuration Data)
pub fn rebuild_bcd() -> String {
    run_cmd("bootrec /rebuildbcd", false)
}

/// Восстановление LogonUI (экран входа Windows)
pub fn restore_logonui() -> Result<(), String> {
    reg_set_string(
        "hklm",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "UIHost",
        "logonui.exe",
    )?;
    reg_set_string(
        "hklm",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Shell",
        "explorer.exe",
    )?;
    reg_set_string(
        "hkcu",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "Shell",
        "",
    ).ok(); // HKCU shell может не существовать — не критично
    Ok(())
}

/// Включение UAC
pub fn enable_uac() -> Result<(), String> {
    reg_set_dword(
        "hklm",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
        1,
    )?;
    reg_set_dword(
        "hklm",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin",
        5,
    ).ok();
    Ok(())
}

/// Восстановление ассоциаций файлов (.exe, .bat, .com, .lnk, .reg)
pub fn restore_file_associations() -> String {
    let script = r#"cmd /c assoc .exe=exefile & assoc .com=comfile & assoc .bat=batfile & assoc .cmd=cmdfile & assoc .reg=regfile & assoc .lnk=lnkfile & assoc .msi=Msi.Package & ftype exefile="%1" %* & ftype comfile="%1" %*"#;
    run_cmd(script, false)
}

/// Восстановление раскладки клавиатуры (удаление Scancode Map)
pub fn restore_keyboard() -> Result<(), String> {
    let _ = reg_delete_value("hklm", r"SYSTEM\CurrentControlSet\Control\Keyboard Layout", "Scancode Map");
    let _ = reg_delete_value("hkcu", r"Keyboard Layout", "Scancode Map");
    // Сброс языков ввода до системного
    Ok(())
}

/// Восстановление настроек мыши по умолчанию
pub fn restore_mouse() -> Result<(), String> {
    reg_set_dword("hkcu", r"Control Panel\Mouse", "SwapMouseButtons", 0)?;
    reg_set_string("hkcu", r"Control Panel\Mouse", "MouseSpeed",      "1").ok();
    reg_set_string("hkcu", r"Control Panel\Mouse", "MouseThreshold1", "6").ok();
    reg_set_string("hkcu", r"Control Panel\Mouse", "MouseThreshold2", "10").ok();
    reg_set_string("hkcu", r"Control Panel\Mouse", "MouseSensitivity", "10").ok();
    Ok(())
}

/// Восстановление шрифтов Windows через SFC
pub fn restore_fonts() -> String {
    let mut out = String::new();
    let targets = [
        r"%windir%\System32\fontsub.dll",
        r"%windir%\System32\t2embed.dll",
        r"%windir%\System32\lpk.dll",
        r"%windir%\System32\usp10.dll",
    ];
    for f in &targets {
        out.push_str(&format!("\n=== sfc /scanfile={f} ===\n"));
        out.push_str(&run_cmd(&format!("sfc /scanfile={f}"), false));
    }
    // Сброс настроек шрифтов GDI
    let _ = reg_set_dword(
        "hkcu",
        r"Control Panel\Desktop",
        "FontSmoothing",
        2,
    );
    out.push_str("\n[Font registry reset done]");
    out
}

/// Восстановление sethc.exe и utilman.exe (антибэкдор на экране входа)
pub fn restore_accessibility_tools() -> String {
    let script = r#"
@echo off
set s32=%windir%\System32
takeown /f "%s32%\sethc.exe" /a >nul 2>&1
icacls "%s32%\sethc.exe" /grant administrators:F >nul 2>&1
sfc /scanfile=%s32%\sethc.exe
takeown /f "%s32%\utilman.exe" /a >nul 2>&1
icacls "%s32%\utilman.exe" /grant administrators:F >nul 2>&1
sfc /scanfile=%s32%\utilman.exe
echo Done
"#;
    run_cmd(script, false)
}

/// Замена sethc.exe и utilman.exe (установка CMD на экране входа — отладочный режим)
/// ВНИМАНИЕ: только для диагностики. Требует отключения Secure Boot и UAC.
pub fn set_accessibility_backdoor(enable: bool) -> String {
    let action = if enable {
        r#"copy /y %windir%\System32\cmd.exe %windir%\System32\sethc.exe & copy /y %windir%\System32\cmd.exe %windir%\System32\utilman.exe"#
    } else {
        r#"sfc /scanfile=%windir%\System32\sethc.exe & sfc /scanfile=%windir%\System32\utilman.exe"#
    };
    run_cmd(action, false)
}

/// Антидебаг: проверка наличия отладчика
pub fn is_debugger_present() -> bool {
    unsafe {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        IsDebuggerPresent().as_bool()
    }
}
