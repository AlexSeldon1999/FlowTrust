// Модуль для работы с процессами Windows через TlHelp32 и PSAPI

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, MAX_PATH},
        Security::{
            GetTokenInformation, LookupAccountSidW, SidTypeUnknown,
            TokenUser, TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
                PROCESSENTRY32W, TH32CS_SNAPPROCESS,
            },
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            SystemInformation::{GetSystemInfo, SYSTEM_INFO},
            Threading::{
                GetProcessTimes, OpenProcess, OpenProcessToken,
                QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_READ,
            },
        },
    },
};

// ── Типы ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ProcessStatus {
    Critical,
    System,
    Suspicious,
    Secure,
}

#[derive(Debug, Serialize, Clone)]
pub struct ProcessInfo {
    pub pid:         u32,
    pub parent_pid:  u32,   // PID родительского процесса (для дерева)
    pub name:        String,
    pub path:        String, // полный путь к исполняемому файлу
    pub user:        String,
    pub status:      ProcessStatus,
    pub cpu_percent: f64,
    pub memory_mb:   f64,
}

// ── Классификация ─────────────────────────────────────────────────────────────

const CRITICAL: &[&str] = &[
    "csrss.exe", "wininit.exe", "lsass.exe", "smss.exe",
    "services.exe", "winlogon.exe", "svchost.exe", "System",
];

const SYSTEM: &[&str] = &[
    "explorer.exe", "dwm.exe", "fontdrvhost.exe", "dllhost.exe",
    "conhost.exe", "sihost.exe", "taskhostw.exe", "runtimebroker.exe",
    "securityhealthsystray.exe", "startmenuexperiencehost.exe",
    "searchindexer.exe", "audiodg.exe", "spoolsv.exe", "ctfmon.exe",
    "registry", "idle",
];

fn classify(name: &str) -> ProcessStatus {
    let lower = name.to_lowercase();
    let crit: HashSet<&str> = CRITICAL.iter().copied().collect();
    let sys: HashSet<&str>  = SYSTEM.iter().copied().collect();

    if crit.contains(lower.as_str()) || crit.contains(name) {
        return ProcessStatus::Critical;
    }
    if sys.contains(lower.as_str()) {
        return ProcessStatus::System;
    }
    if lower.trim_end_matches(".exe").chars().filter(|c| c.is_numeric()).count() > 4 {
        return ProcessStatus::Suspicious;
    }
    ProcessStatus::Secure
}

// ── WinAPI-утилиты ────────────────────────────────────────────────────────────

fn filetime_u64(ft: &windows::Win32::Foundation::FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

fn cpu_count() -> u32 {
    unsafe {
        let mut info = SYSTEM_INFO::default();
        GetSystemInfo(&mut info);
        info.dwNumberOfProcessors.max(1)
    }
}

/// Полный путь к исполняемому файлу процесса
pub unsafe fn proc_path(pid: u32) -> String {
    if pid == 0 || pid == 4 {
        return "System".to_string();
    }
    let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
        Ok(h) if !h.is_invalid() => h,
        _ => return String::new(),
    };

    let mut buf = vec![0u16; MAX_PATH as usize];
    let mut len = MAX_PATH;
    let path = if QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_ok() {
        String::from_utf16_lossy(&buf[..len as usize])
    } else {
        String::new()
    };
    let _ = CloseHandle(h);
    path
}

/// Суммарное время CPU процесса (kernel + user) в единицах 100 нс
unsafe fn proc_cpu_time(pid: u32) -> Option<u64> {
    if pid == 0 { return None; }
    let h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()?;
    if h.is_invalid() { return None; }
    let (mut cr, mut ex, mut k, mut u) = Default::default();
    let ok = GetProcessTimes(h, &mut cr, &mut ex, &mut k, &mut u).is_ok();
    let _ = CloseHandle(h);
    ok.then(|| filetime_u64(&k) + filetime_u64(&u))
}

/// Working Set процесса в МБ
unsafe fn proc_memory_mb(pid: u32) -> f64 {
    if pid == 0 { return 0.0; }
    let h = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
        Ok(h) if !h.is_invalid() => h,
        _ => return 0.0,
    };
    let mut pmc = PROCESS_MEMORY_COUNTERS::default();
    let mb = if GetProcessMemoryInfo(h, &mut pmc, std::mem::size_of_val(&pmc) as u32).is_ok() {
        pmc.WorkingSetSize as f64 / 1_048_576.0
    } else { 0.0 };
    let _ = CloseHandle(h);
    mb
}

/// Имя владельца процесса через Token → SID → LookupAccountSid
unsafe fn proc_owner(pid: u32) -> String {
    if pid == 0 || pid == 4 { return "SYSTEM".to_string(); }

    let h = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
        Ok(h) if !h.is_invalid() => h,
        _ => return "N/A".to_string(),
    };
    let mut tok = HANDLE::default();
    if OpenProcessToken(h, TOKEN_QUERY, &mut tok).is_err() {
        let _ = CloseHandle(h);
        return "N/A".to_string();
    }
    let _ = CloseHandle(h);

    let mut len = 0u32;
    let _ = GetTokenInformation(tok, TokenUser, None, 0, &mut len);
    if len == 0 { let _ = CloseHandle(tok); return "N/A".to_string(); }

    let mut buf = vec![0u8; len as usize];
    let owner = if GetTokenInformation(tok, TokenUser, Some(buf.as_mut_ptr() as *mut _), len, &mut len).is_ok() {
        let tu  = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = tu.User.Sid;
        let mut nb = vec![0u16; MAX_PATH as usize];
        let mut db = vec![0u16; MAX_PATH as usize];
        let (mut nl, mut dl) = (MAX_PATH, MAX_PATH);
        let mut st = SidTypeUnknown;
        if LookupAccountSidW(None, sid, PWSTR(nb.as_mut_ptr()), &mut nl,
                              PWSTR(db.as_mut_ptr()), &mut dl, &mut st).is_ok() {
            let name   = String::from_utf16_lossy(&nb[..nl as usize]);
            let domain = String::from_utf16_lossy(&db[..dl as usize]);
            if domain.is_empty() { name } else { format!("{domain}\\{name}") }
        } else { "N/A".to_string() }
    } else { "N/A".to_string() };

    let _ = CloseHandle(tok);
    owner
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Перечисление DLL процесса ─────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Clone)]
pub struct DllInfo {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub size: u64,
}

/// Получить список загруженных модулей (DLL) для указанного PID.
pub fn get_process_dlls(pid: u32) -> Vec<DllInfo> {
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleInformation,
        GetModuleFileNameExW, MODULEINFO,
    };
    use windows::Win32::Foundation::HMODULE;

    if pid == 0 { return vec![]; }
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) if !h.is_invalid() => h,
            _ => return vec![],
        };

        let mut modules: Vec<HMODULE> = vec![HMODULE::default(); 1024];
        let mut needed: u32 = 0;
        if EnumProcessModules(
            h,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut needed,
        ).is_err() {
            let _ = CloseHandle(h);
            return vec![];
        }

        let count = (needed as usize) / std::mem::size_of::<HMODULE>();
        let mut result = Vec::with_capacity(count);

        for &hmod in &modules[..count.min(modules.len())] {
            let mut buf = vec![0u16; MAX_PATH as usize];
            let len = GetModuleFileNameExW(h, hmod, &mut buf);
            let path = if len > 0 {
                String::from_utf16_lossy(&buf[..len as usize])
            } else {
                String::new()
            };
            let name = path.split('\\').last().unwrap_or("").to_string();

            let mut info = MODULEINFO::default();
            let _ = GetModuleInformation(
                h, hmod, &mut info,
                std::mem::size_of::<MODULEINFO>() as u32,
            );

            result.push(DllInfo {
                name,
                path,
                base: info.lpBaseOfDll as u64,
                size: info.SizeOfImage as u64,
            });
        }

        let _ = CloseHandle(h);
        result
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Поиск скрытых процессов ───────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Clone)]
pub struct HiddenProcess {
    pub pid:          u32,
    pub in_tlhelp:    bool,  // виден в TlHelp32 (CreateToolhelp32Snapshot)
    pub in_psapi:     bool,  // виден в PSAPI EnumProcesses
    pub can_open:     bool,  // можно открыть через OpenProcess
    pub path:         String,
    pub reason:       String,
}

/// Сравнивает список PID из TlHelp32 и PSAPI EnumProcesses.
/// PID, присутствующий только в одном из списков — потенциально скрытый.
/// Дополнительно сканирует PID 4–32760 с шагом 4 (brute-force для DKOM-руткитов).
pub fn find_hidden_processes() -> Vec<HiddenProcess> {
    use windows::Win32::System::ProcessStatus::EnumProcesses;

    // 1. TlHelp32 snapshot
    let tlhelp_pids: std::collections::HashSet<u32> = unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) if !h.is_invalid() => h,
            _ => return vec![],
        };
        let mut e = PROCESSENTRY32W::default();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut pids = std::collections::HashSet::new();
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                pids.insert(e.th32ProcessID);
                e = PROCESSENTRY32W::default();
                e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut e).is_err() { break; }
            }
        }
        let _ = CloseHandle(snap);
        pids
    };

    // 2. PSAPI EnumProcesses
    let psapi_pids: std::collections::HashSet<u32> = unsafe {
        let mut pids_buf = vec![0u32; 4096];
        let mut needed: u32 = 0;
        let ok = EnumProcesses(
            pids_buf.as_mut_ptr(),
            (pids_buf.len() * 4) as u32,
            &mut needed,
        );
        if ok.is_ok() {
            let count = (needed as usize) / 4;
            pids_buf[..count].iter().copied().collect()
        } else {
            std::collections::HashSet::new()
        }
    };

    let mut result: Vec<HiddenProcess> = Vec::new();

    // 3. Находим расхождения
    for &pid in tlhelp_pids.symmetric_difference(&psapi_pids) {
        if pid <= 4 { continue; } // пропускаем System и Idle
        let in_tl = tlhelp_pids.contains(&pid);
        let in_ps = psapi_pids.contains(&pid);
        let (can_open, path) = unsafe {
            match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                Ok(h) if !h.is_invalid() => {
                    let p = proc_path(pid);
                    let _ = CloseHandle(h);
                    (true, p)
                }
                _ => (false, String::new()),
            }
        };
        let reason = match (in_tl, in_ps) {
            (true, false)  => "Виден в TlHelp32, скрыт в PSAPI — подозрение на DKOM".to_string(),
            (false, true)  => "Виден в PSAPI, скрыт в TlHelp32 — нестандартный процесс".to_string(),
            _ => "Расхождение списков".to_string(),
        };
        result.push(HiddenProcess { pid, in_tlhelp: in_tl, in_psapi: in_ps, can_open, path, reason });
    }

    // 4. Brute-force: попытка открыть PID не из обоих списков.
    // Только если удаётся получить путь к образу — иначе это ядровый объект (Job, ALPC, GPU),
    // а не скрытый процесс (false-positive).
    let all_known: std::collections::HashSet<u32> = tlhelp_pids.union(&psapi_pids).copied().collect();
    unsafe {
        for pid in (4u32..65536).step_by(4) {
            if all_known.contains(&pid) { continue; }
            if let Ok(h) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                if !h.is_invalid() {
                    let path = proc_path(pid);
                    let _ = CloseHandle(h);
                    // Пропускаем ядровые объекты — у реального скрытого процесса есть путь
                    if path.is_empty() { continue; }
                    result.push(HiddenProcess {
                        pid,
                        in_tlhelp: false,
                        in_psapi:  false,
                        can_open:  true,
                        path,
                        reason: "Скрыт от TlHelp32 и PSAPI — возможный DKOM-руткит".to_string(),
                    });
                }
            }
        }
    }

    result.sort_by_key(|p| p.pid);
    result
}

// ── Главная функция ───────────────────────────────────────────────────────────

pub fn get_process_list() -> Vec<ProcessInfo> {
    // 1. Снимок TlHelp32 — захватываем PID, parent_pid, имя
    let entries: Vec<(u32, u32, String)> = unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) if !h.is_invalid() => h,
            _ => return vec![],
        };
        let mut e = PROCESSENTRY32W::default();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut list = Vec::new();
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                let n = &e.szExeFile;
                let len = n.iter().position(|&c| c == 0).unwrap_or(n.len());
                list.push((
                    e.th32ProcessID,
                    e.th32ParentProcessID,
                    String::from_utf16_lossy(&n[..len]),
                ));
                e = PROCESSENTRY32W::default();
                e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut e).is_err() { break; }
            }
        }
        let _ = CloseHandle(snap);
        list
    };

    let pids: Vec<u32> = entries.iter().map(|(pid, _, _)| *pid).collect();

    // 2. Первый замер CPU
    let t1: HashMap<u32, u64> = pids.iter()
        .filter_map(|&pid| unsafe { proc_cpu_time(pid).map(|t| (pid, t)) })
        .collect();
    let wall = std::time::Instant::now();

    std::thread::sleep(std::time::Duration::from_millis(300));

    // 3. Второй замер CPU
    let t2: HashMap<u32, u64> = pids.iter()
        .filter_map(|&pid| unsafe { proc_cpu_time(pid).map(|t| (pid, t)) })
        .collect();

    let elapsed_100ns = wall.elapsed().as_nanos() as f64 / 100.0;
    let ncpu = cpu_count() as f64;

    // 4. Сборка
    let mut result: Vec<ProcessInfo> = entries.iter().map(|(pid, parent_pid, name)| {
        let cpu_percent = match (t1.get(pid), t2.get(pid)) {
            (Some(&a), Some(&b)) if elapsed_100ns > 0.0 => {
                let delta = b.saturating_sub(a) as f64;
                (delta / (elapsed_100ns * ncpu) * 100.0).min(100.0)
            }
            _ => 0.0,
        };
        let memory_mb = unsafe { proc_memory_mb(*pid) };
        let user      = unsafe { proc_owner(*pid) };
        let path      = unsafe { proc_path(*pid) };
        let status    = classify(name);

        ProcessInfo {
            pid:        *pid,
            parent_pid: *parent_pid,
            name:       name.clone(),
            path,
            user,
            status,
            cpu_percent: (cpu_percent * 100.0).round() / 100.0,
            memory_mb:   (memory_mb   *  10.0).round() /  10.0,
        }
    }).collect();

    // Сортировка: Critical → Suspicious → System → Secure, внутри по памяти
    result.sort_by(|a, b| {
        let rank = |s: &ProcessStatus| match s {
            ProcessStatus::Critical   => 0,
            ProcessStatus::Suspicious => 1,
            ProcessStatus::System     => 2,
            ProcessStatus::Secure     => 3,
        };
        rank(&a.status).cmp(&rank(&b.status))
            .then(b.memory_mb.partial_cmp(&a.memory_mb).unwrap_or(std::cmp::Ordering::Equal))
    });

    result
}
