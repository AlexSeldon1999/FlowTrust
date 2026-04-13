// Модуль автозагрузки: Run/RunOnce, Winlogon, AppInit_DLLs, Планировщик задач.

use serde::Serialize;
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegEnumValueW, RegOpenKeyExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ, KEY_WRITE,
    REG_SZ, REG_EXPAND_SZ, REG_VALUE_TYPE,
};
use windows::core::PCWSTR;

// ── Типы ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum StartupSource {
    RegistryRun,
    RegistryRunOnce,
    Winlogon,
    AppInitDlls,
    ScheduledTask,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum StartupHive { Hklm, Hkcu }

#[derive(Debug, Serialize, Clone)]
pub struct StartupEntry {
    pub name:        String,
    pub command:     String,
    pub location:    String,
    pub hive:        StartupHive,
    pub suspicious:  bool,
    pub source:      StartupSource,
}

// ── Ключи реестра Run/RunOnce ─────────────────────────────────────────────────

const RUN_KEYS: &[(&str, StartupSource)] = &[
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     StartupSource::RegistryRun),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", StartupSource::RegistryRunOnce),
    (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", StartupSource::RegistryRun),
];

// ── Эвристика ─────────────────────────────────────────────────────────────────

/// Является ли значение Shell стандартным explorer.exe (любой путь, любой регистр).
fn is_standard_shell(lower: &str) -> bool {
    lower == "explorer.exe"
        || lower.ends_with("\\explorer.exe")
        || lower.ends_with("/explorer.exe")
}

fn is_suspicious(command: &str) -> bool {
    let lower = command.to_lowercase();
    let sus = [
        r"\temp\", r"\tmp\", r"\appdata\local\temp",
        r"\downloads\", r"\desktop\",
        r"powershell", r"cmd.exe /c",
        r"mshta", r"wscript", r"cscript",
        r"rundll32", r"regsvr32",
        r"%temp%", r"%tmp%",
        r"base64", r"encoded",
    ];
    sus.iter().any(|p| lower.contains(p))
}

// ── Хелпер: HKEY из строки ────────────────────────────────────────────────────

fn hive_from_str(hive_str: &str) -> HKEY {
    if hive_str.eq_ignore_ascii_case("hklm") {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    }
}

// ── Хелпер: прочитать строковое значение реестра ─────────────────────────────

pub fn reg_read_string(hive_str: &str, key: &str, value_name: &str) -> Option<String> {
    unsafe {
        let wide_key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(hive_from_str(hive_str), PCWSTR(wide_key.as_ptr()), 0, KEY_READ, &mut hkey).is_err() {
            return None;
        }
        let target = value_name.to_lowercase();
        let mut index = 0u32;
        let mut found: Option<String> = None;
        loop {
            let mut name_buf = vec![0u16; MAX_PATH as usize];
            let mut name_len = MAX_PATH;
            let mut data_buf = vec![0u8; 4096];
            let mut data_len = data_buf.len() as u32;
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
            if name == target && (vtype == REG_SZ.0 || vtype == REG_EXPAND_SZ.0) {
                let data_u16: Vec<u16> = data_buf[..data_len as usize]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                found = Some(String::from_utf16_lossy(&data_u16).trim_end_matches('\0').to_string());
                break;
            }
            index += 1;
        }
        let _ = RegCloseKey(hkey);
        found
    }
}

// ── Чтение Run/RunOnce ────────────────────────────────────────────────────────

unsafe fn read_run_key(
    root: HKEY,
    hive: StartupHive,
    subkey: &str,
    source: StartupSource,
    out: &mut Vec<StartupEntry>,
) {
    let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY::default();
    if RegOpenKeyExW(root, PCWSTR(wide.as_ptr()), 0, KEY_READ, &mut hkey).is_err() {
        return;
    }
    let mut index = 0u32;
    loop {
        let mut name_buf  = vec![0u16; MAX_PATH as usize];
        let mut name_len  = MAX_PATH;
        let mut data_buf  = vec![0u8; 2048];
        let mut data_len  = data_buf.len() as u32;
        let mut value_type = 0u32;

        if RegEnumValueW(
            hkey, index,
            windows::core::PWSTR(name_buf.as_mut_ptr()),
            &mut name_len,
            None,
            Some(&mut value_type),
            Some(data_buf.as_mut_ptr()),
            Some(&mut data_len),
        ).is_err() { break; }

        if value_type == REG_SZ.0 || value_type == REG_EXPAND_SZ.0 {
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let data_u16: Vec<u16> = data_buf[..data_len as usize]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            let command = String::from_utf16_lossy(&data_u16)
                .trim_end_matches('\0').to_string();
            let suspicious = is_suspicious(&command);
            out.push(StartupEntry {
                name, command,
                location: subkey.to_string(),
                hive: hive.clone(),
                suspicious,
                source: source.clone(),
            });
        }
        index += 1;
    }
    let _ = RegCloseKey(hkey);
}

// ── Winlogon и AppInit_DLLs ───────────────────────────────────────────────────

fn get_winlogon_entries() -> Vec<StartupEntry> {
    let mut entries = Vec::new();

    // HKLM Winlogon — Userinit, Shell, UIHost
    let hklm_winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    for &val in &["Userinit", "Shell", "UIHost"] {
        if let Some(data) = reg_read_string("hklm", hklm_winlogon, val) {
            if !data.is_empty() {
                let lower = data.trim().to_lowercase();
                let suspicious = is_suspicious(&data)
                    || (val == "Shell"    && !is_standard_shell(&lower))
                    || (val == "Userinit" && !lower.contains("userinit.exe"));
                entries.push(StartupEntry {
                    name:      val.to_string(),
                    command:   data,
                    location:  hklm_winlogon.to_string(),
                    hive:      StartupHive::Hklm,
                    suspicious,
                    source:    StartupSource::Winlogon,
                });
            }
        }
    }
    // HKCU Winlogon — Shell (подмена shell пользователя)
    // Подозрительно только если это НЕ стандартный explorer.exe
    let hkcu_winlogon = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
    if let Some(data) = reg_read_string("hkcu", hkcu_winlogon, "Shell") {
        if !data.is_empty() {
            let lower = data.trim().to_lowercase();
            let suspicious = !is_standard_shell(&lower) || is_suspicious(&data);
            entries.push(StartupEntry {
                name:      "Shell (HKCU)".to_string(),
                command:   data.clone(),
                location:  hkcu_winlogon.to_string(),
                hive:      StartupHive::Hkcu,
                suspicious,
                source:    StartupSource::Winlogon,
            });
        }
    }

    // AppInit_DLLs — HKLM + WOW64
    for &key in &[
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ] {
        if let Some(data) = reg_read_string("hklm", key, "AppInit_DLLs") {
            if !data.is_empty() {
                entries.push(StartupEntry {
                    name:      "AppInit_DLLs".to_string(),
                    command:   data,
                    location:  key.to_string(),
                    hive:      StartupHive::Hklm,
                    suspicious: true, // Любая непустая AppInit_DLLs — подозрительна
                    source:    StartupSource::AppInitDlls,
                });
            }
        }
    }
    entries
}

// ── Планировщик задач через PowerShell ───────────────────────────────────────

fn get_scheduled_tasks() -> Vec<StartupEntry> {
    let ps_cmd = r#"Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object { $act = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; '; "$($_.TaskPath)$($_.TaskName)|$($_.State)|$act" }"#;
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd])
        .output();

    let out = match output {
        Ok(o) => o,
        Err(_) => return vec![],
    };

    let text = String::from_utf8_lossy(&out.stdout);

    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(3, '|').collect();
            if parts.len() < 3 { return None; }
            let full_name = parts[0].trim().to_string();
            let state     = parts[1].trim().to_string();
            let command   = parts[2].trim().to_string();
            let name = full_name.split('\\').last().unwrap_or(&full_name).to_string();
            // Пропускаем Microsoft-системные задачи (они не вирусы)
            if full_name.starts_with("\\Microsoft\\Windows\\") { return None; }
            let suspicious = is_suspicious(&command)
                || command.to_lowercase().contains("powershell")
                || command.to_lowercase().contains("wscript")
                || command.to_lowercase().contains("mshta");
            Some(StartupEntry {
                name,
                command,
                location: format!("Задача: {} [{}]", full_name, state),
                hive:     StartupHive::Hklm,
                suspicious,
                source:   StartupSource::ScheduledTask,
            })
        })
        .collect()
}

// ── Публичные функции чтения ──────────────────────────────────────────────────

/// Только Run/RunOnce из реестра (обратная совместимость)
pub fn get_startup_entries() -> Vec<StartupEntry> {
    let mut result = Vec::new();
    unsafe {
        for &(key, ref src) in RUN_KEYS {
            read_run_key(HKEY_LOCAL_MACHINE, StartupHive::Hklm, key, src.clone(), &mut result);
            read_run_key(HKEY_CURRENT_USER,  StartupHive::Hkcu, key, src.clone(), &mut result);
        }
    }
    result.sort_by(|a, b| b.suspicious.cmp(&a.suspicious).then(a.name.cmp(&b.name)));
    result
}

/// Все источники: реестр + Winlogon + AppInit + Планировщик задач
pub fn get_startup_full() -> Vec<StartupEntry> {
    let mut result = get_startup_entries();
    result.extend(get_winlogon_entries());
    result.extend(get_scheduled_tasks());
    result.sort_by(|a, b| b.suspicious.cmp(&a.suspicious).then(a.name.cmp(&b.name)));
    result
}

// ── Управление записями Run/RunOnce ──────────────────────────────────────────

pub fn delete_startup_entry(name: &str, hive_str: &str, location: &str) -> Result<(), String> {
    unsafe {
        let root = hive_from_str(hive_str);
        let wide_key: Vec<u16> = location.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();
        RegOpenKeyExW(root, PCWSTR(wide_key.as_ptr()), 0, KEY_WRITE, &mut hkey)
            .map_err(|e| format!("RegOpenKeyExW: {e}"))?;
        let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let err = RegDeleteValueW(hkey, PCWSTR(wide_name.as_ptr()));
        let _ = RegCloseKey(hkey);
        if err.is_err() { Err(format!("RegDeleteValueW: {:?}", err)) } else { Ok(()) }
    }
}

pub fn edit_startup_entry(name: &str, hive_str: &str, location: &str, new_command: &str) -> Result<(), String> {
    unsafe {
        let root = hive_from_str(hive_str);
        let wide_key:  Vec<u16> = location.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();
        RegOpenKeyExW(root, PCWSTR(wide_key.as_ptr()), 0, KEY_WRITE, &mut hkey)
            .map_err(|e| format!("RegOpenKeyExW: {e}"))?;
        let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let wide_val:  Vec<u16> = new_command.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = std::slice::from_raw_parts(wide_val.as_ptr() as *const u8, wide_val.len() * 2);
        let err = RegSetValueExW(hkey, PCWSTR(wide_name.as_ptr()), 0, REG_VALUE_TYPE(REG_SZ.0), Some(bytes));
        let _ = RegCloseKey(hkey);
        if err.is_err() { Err(format!("RegSetValueExW: {:?}", err)) } else { Ok(()) }
    }
}

pub fn open_file_location(path: &str) -> Result<(), String> {
    std::process::Command::new("explorer")
        .arg(format!("/select,{}", path))
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn delete_file_at_path(path: &str) -> Result<(), String> {
    std::fs::remove_file(path).map_err(|e| e.to_string())
}
