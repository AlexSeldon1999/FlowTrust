// Модуль форензики: анализ угроз процессов + проверка цифровых подписей.
//
// WinVerifyTrust вызывается через ручные repr(C) структуры, т.к. windows 0.52
// не экспортирует WINTRUST_DATA в биндинги.

use serde::Serialize;
use crate::process::{ProcessInfo, ProcessStatus};

// ── Типы угроз ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatType {
    Masquerading,
    SuspiciousPath,
    NoImage,
    Unsigned,
}

#[derive(Debug, Serialize, Clone, PartialEq, PartialOrd)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Serialize, Clone)]
pub struct ThreatIndicator {
    pub pid:          u32,
    pub process_name: String,
    pub path:         String,
    pub threat_type:  ThreatType,
    pub description:  String,
    pub severity:     Severity,
}

// ── Карта системных процессов → легитимные пути ───────────────────────────────

const SYSTEM32: &str = r"c:\windows\system32\";
const WINDOWS:  &str = r"c:\windows\";

const KNOWN_PATHS: &[(&str, &[&str])] = &[
    ("csrss.exe",    &[SYSTEM32]),
    ("lsass.exe",    &[SYSTEM32]),
    ("services.exe", &[SYSTEM32]),
    ("svchost.exe",  &[SYSTEM32]),
    ("winlogon.exe", &[SYSTEM32]),
    ("wininit.exe",  &[SYSTEM32]),
    ("smss.exe",     &[SYSTEM32]),
    ("explorer.exe", &[WINDOWS]),
    ("taskhostw.exe",&[SYSTEM32]),
    ("dwm.exe",      &[SYSTEM32]),
    ("spoolsv.exe",  &[SYSTEM32]),
];

const SUSPICIOUS_DIRS: &[&str] = &[
    r"\temp\", r"\tmp\", r"\appdata\local\temp\",
    r"\downloads\", r"\desktop\", r"\recycle", r"\public\",
];

// ── WinVerifyTrust через ручные repr(C) структуры ────────────────────────────
//
// WINTRUST_DATA не экспортирован в windows-rs 0.52 — определяем сами.
// Источник: wintrust.h из Windows SDK.

use windows::core::GUID;

#[repr(C)]
struct WintrustFileInfo {
    cb_struct:         u32,
    pcwsz_file_path:   *const u16,
    h_file:            *mut std::ffi::c_void,
    pg_known_subject:  *mut GUID,
}

// Структура выровнена по 4/8 байт в зависимости от платформы.
// union dwUnionChoice выбираем pFile, остальные поля union = 0.
#[repr(C)]
struct WintrustData {
    cb_struct:              u32,
    p_policy_callback_data: *mut std::ffi::c_void,
    p_sip_client_data:      *mut std::ffi::c_void,
    dw_ui_choice:           u32,   // WTD_UI_NONE = 2
    fdw_revocation_checks:  u32,   // WTD_REVOKE_NONE = 0
    dw_union_choice:        u32,   // WTD_CHOICE_FILE = 1
    p_file:                 *mut WintrustFileInfo,
    dw_state_action:        u32,   // WTD_STATEACTION_VERIFY = 1
    h_wvt_state_data:       *mut std::ffi::c_void,
    pwsz_url_reference:     *const u16,
    dw_prov_flags:          u32,
    dw_ui_context:          u32,
    p_signature_settings:   *mut std::ffi::c_void,
}

// WinVerifyTrust из wintrust.dll
#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(
        hwnd:        *mut std::ffi::c_void, // HWND — NULL для без окна
        pg_action_id: *mut GUID,
        p_wvt_data:  *mut WintrustData,
    ) -> i32; // LONG
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
const VERIFY_V2: GUID = GUID {
    data1: 0x00aac56b,
    data2: 0xcd44,
    data3: 0x11d0,
    data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};

/// Проверяет наличие доверенной цифровой подписи у файла.
/// WTD_REVOKE_NONE — без сетевых запросов CRL (быстро).
/// Возвращает true = подпись валидна.
pub fn is_signed(path: &str) -> bool {
    if path.is_empty() { return false; }

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut file_info = WintrustFileInfo {
            cb_struct:        std::mem::size_of::<WintrustFileInfo>() as u32,
            pcwsz_file_path:  wide.as_ptr(),
            h_file:           std::ptr::null_mut(),
            pg_known_subject: std::ptr::null_mut(),
        };

        let mut trust_data = WintrustData {
            cb_struct:              std::mem::size_of::<WintrustData>() as u32,
            p_policy_callback_data: std::ptr::null_mut(),
            p_sip_client_data:      std::ptr::null_mut(),
            dw_ui_choice:           2, // WTD_UI_NONE
            fdw_revocation_checks:  0, // WTD_REVOKE_NONE
            dw_union_choice:        1, // WTD_CHOICE_FILE
            p_file:                 &mut file_info,
            dw_state_action:        1, // WTD_STATEACTION_VERIFY
            h_wvt_state_data:       std::ptr::null_mut(),
            pwsz_url_reference:     std::ptr::null(),
            dw_prov_flags:          0,
            dw_ui_context:          0,
            p_signature_settings:   std::ptr::null_mut(),
        };

        let mut action = VERIFY_V2;
        let result = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut trust_data,
        );

        // Закрываем хендл состояния
        trust_data.dw_state_action = 2; // WTD_STATEACTION_CLOSE
        WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut trust_data);

        result == 0 // S_OK = подпись валидна
    }
}

// ── Проверки ──────────────────────────────────────────────────────────────────

fn check_masquerading(proc: &ProcessInfo) -> Option<ThreatIndicator> {
    let name_lower = proc.name.to_lowercase();
    let path_lower = proc.path.to_lowercase();

    for &(sys_name, allowed_dirs) in KNOWN_PATHS {
        if name_lower != sys_name { continue; }

        if path_lower.is_empty() {
            // Критичные/системные процессы без пути — это норма (защищённые процессы, ядро).
            // Флагим только когда статус неизвестен или подозрителен.
            match proc.status {
                ProcessStatus::Critical | ProcessStatus::System => return None,
                _ => {}
            }
            return Some(ThreatIndicator {
                pid:          proc.pid,
                process_name: proc.name.clone(),
                path:         proc.path.clone(),
                threat_type:  ThreatType::NoImage,
                description:  format!("'{}' — путь к образу недоступен (возможный hollow process)", proc.name),
                severity:     Severity::High,
            });
        }

        if !allowed_dirs.iter().any(|d| path_lower.starts_with(d)) {
            return Some(ThreatIndicator {
                pid:          proc.pid,
                process_name: proc.name.clone(),
                path:         proc.path.clone(),
                threat_type:  ThreatType::Masquerading,
                description:  format!("'{}' запущен из нестандартного пути: {}", proc.name, proc.path),
                severity:     Severity::Critical,
            });
        }
    }
    None
}

fn check_suspicious_path(proc: &ProcessInfo) -> Option<ThreatIndicator> {
    if proc.path.is_empty() { return None; }
    let path_lower = proc.path.to_lowercase();
    let hit = SUSPICIOUS_DIRS.iter().find(|&&d| path_lower.contains(d))?;
    Some(ThreatIndicator {
        pid:          proc.pid,
        process_name: proc.name.clone(),
        path:         proc.path.clone(),
        threat_type:  ThreatType::SuspiciousPath,
        description:  format!("Запущен из подозрительной директории ({})", hit.trim_matches('\\')),
        severity:     Severity::Medium,
    })
}

fn check_unsigned(proc: &ProcessInfo) -> Option<ThreatIndicator> {
    // Системные процессы пропускаем — у них всегда есть подпись
    match proc.status {
        ProcessStatus::Critical | ProcessStatus::System => return None,
        _ => {}
    }
    if proc.path.is_empty() { return None; }
    // Процессы из системных папок Microsoft — быстрый пропуск
    let path_lower = proc.path.to_lowercase();
    if path_lower.starts_with(r"c:\windows\") ||
       path_lower.starts_with(r"c:\program files\") ||
       path_lower.starts_with(r"c:\program files (x86)\") {
        return None;
    }

    if !is_signed(&proc.path) {
        Some(ThreatIndicator {
            pid:          proc.pid,
            process_name: proc.name.clone(),
            path:         proc.path.clone(),
            threat_type:  ThreatType::Unsigned,
            description:  format!("'{}' не имеет доверенной цифровой подписи", proc.name),
            severity:     Severity::Low,
        })
    } else {
        None
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── SHA-256 и карантин ────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

use sha2::{Digest, Sha256};

/// Вычислить SHA-256 хэш файла. Возвращает hex-строку или строку с ошибкой.
pub fn compute_sha256(path: &str) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("Не удалось открыть файл: {e}"))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .map_err(|e| format!("Ошибка чтения: {e}"))?;
    let result = hasher.finalize();
    Ok(result.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Переместить файл в карантин (%APPDATA%\FlowTrust\Quarantine\).
/// Переименовывает файл в <sha256>.quarantined.
/// Возвращает новый путь к файлу в карантине.
pub fn quarantine_file(path: &str) -> Result<String, String> {
    let qdir = {
        let appdata = std::env::var("APPDATA")
            .unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
        std::path::PathBuf::from(appdata)
            .join("FlowTrust")
            .join("Quarantine")
    };
    std::fs::create_dir_all(&qdir)
        .map_err(|e| format!("Не удалось создать папку карантина: {e}"))?;

    let hash = compute_sha256(path)?;
    let dest = qdir.join(format!("{}.quarantined", hash));

    // rename работает только внутри одного диска; при кросс-дисковом переносе
    // падаем обратно на copy + delete.
    if std::fs::rename(path, &dest).is_err() {
        std::fs::copy(path, &dest)
            .map_err(|e| format!("Ошибка копирования в карантин: {e}"))?;
        std::fs::remove_file(path)
            .map_err(|e| format!("Ошибка удаления оригинала: {e}"))?;
    }

    // Сохраняем метаданные рядом
    let meta = format!(
        "{{\"original\":\"{}\",\"sha256\":\"{}\",\"quarantined_at\":\"{}\"}}",
        path.replace('\\', "\\\\"),
        hash,
        chrono_now_str(),
    );
    let _ = std::fs::write(qdir.join(format!("{}.meta.json", hash)), meta);

    Ok(dest.to_string_lossy().to_string())
}

fn chrono_now_str() -> String {
    // Простая метка времени без внешних зависимостей
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Конвертируем UNIX-время в читаемый формат
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Примерная дата (не точная) — достаточно для логирования
    format!("day_{}_{}:{:02}:{:02}_UTC", days, h, m, s)
}

// ── Публичная функция ─────────────────────────────────────────────────────────

pub fn analyze(processes: &[ProcessInfo]) -> Vec<ThreatIndicator> {
    let mut indicators: Vec<ThreatIndicator> = processes.iter()
        .flat_map(|p| [
            check_masquerading(p),
            check_suspicious_path(p),
            check_unsigned(p),
        ].into_iter().flatten())
        .collect();

    indicators.sort_by(|a, b| {
        let rank = |s: &Severity| match s {
            Severity::Critical => 0u8,
            Severity::High     => 1,
            Severity::Medium   => 2,
            Severity::Low      => 3,
        };
        rank(&a.severity).cmp(&rank(&b.severity))
            .then(a.process_name.cmp(&b.process_name))
    });
    indicators
}
