// Запрет консольного окна в release-сборке на Windows
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod filemanager;
mod forensics;
mod network;
mod process;
mod recovery;
mod startup;


use forensics::ThreatIndicator;
use network::ConnectionInfo;
use process::{ProcessInfo, DllInfo, HiddenProcess};
use startup::StartupEntry;
use tauri::{CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem};

// ── Защита: антидебаг (только release) ───────────────────────────────────────

#[cfg(not(debug_assertions))]
fn security_check() {
    if recovery::is_debugger_present() {
        std::process::exit(1);
    }
}
#[cfg(debug_assertions)]
fn security_check() {}

// ══════════════════════════════════════════════════════════════════════════════
// ── Команды: процессы ─────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

#[tauri::command]
async fn get_processes() -> Vec<ProcessInfo> {
    tauri::async_runtime::spawn_blocking(|| process::get_process_list())
        .await.unwrap_or_default()
}

#[tauri::command]
async fn get_connections() -> Vec<ConnectionInfo> {
    tauri::async_runtime::spawn_blocking(|| {
        let procs   = process::get_process_list();
        let pid_map = procs.into_iter().map(|p| (p.pid, p.name)).collect();
        network::get_connections(pid_map)
    }).await.unwrap_or_default()
}

#[tauri::command]
async fn get_startup() -> Vec<StartupEntry> {
    tauri::async_runtime::spawn_blocking(startup::get_startup_entries)
        .await.unwrap_or_default()
}

#[tauri::command]
async fn get_startup_full_cmd() -> Vec<StartupEntry> {
    tauri::async_runtime::spawn_blocking(startup::get_startup_full)
        .await.unwrap_or_default()
}

#[tauri::command]
async fn get_threats() -> Vec<ThreatIndicator> {
    tauri::async_runtime::spawn_blocking(|| {
        let procs = process::get_process_list();
        forensics::analyze(&procs)
    }).await.unwrap_or_default()
}

#[tauri::command]
async fn check_signature(path: String) -> String {
    tauri::async_runtime::spawn_blocking(move || {
        if path.is_empty() { return "UNKNOWN".to_string(); }
        if forensics::is_signed(&path) { "TRUSTED".to_string() } else { "UNTRUSTED".to_string() }
    }).await.unwrap_or_else(|_| "UNKNOWN".to_string())
}

#[tauri::command]
async fn kill_process(pid: u32) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || kill_impl(pid))
        .await.map_err(|e| e.to_string())?
}

fn kill_impl(pid: u32) -> Result<(), String> {
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE},
    };
    if pid == 0 || pid == 4 { return Err("Невозможно завершить системный процесс".to_string()); }
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| format!("OpenProcess PID {pid}: {e}"))?;
        if h.is_invalid() { return Err(format!("Invalid handle PID {pid}")); }
        let res = TerminateProcess(h, 1).map_err(|e| format!("TerminateProcess PID {pid}: {e}"));
        let _ = CloseHandle(h);
        res
    }
}

// ── Команды: критичность процесса ────────────────────────────────────────────

/// Снять/установить флаг критичности процесса (ProcessBreakOnTermination).
/// critical=false — процесс перестаёт быть критичным (не вызывает BSOD при завершении).
#[tauri::command]
async fn set_process_critical(pid: u32, critical: bool) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || set_critical_impl(pid, critical))
        .await.map_err(|e| e.to_string())?
}

fn set_critical_impl(pid: u32, critical: bool) -> Result<(), String> {
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Threading::{OpenProcess, PROCESS_SET_INFORMATION, PROCESS_QUERY_INFORMATION},
    };

    // NtSetInformationProcess — недокументированная, но стабильная NT API.
    // ProcessBreakOnTermination (класс 29): 0 = не критичный, 1 = критичный.
    #[link(name = "ntdll")]
    extern "system" {
        fn NtSetInformationProcess(
            process_handle: isize,
            process_information_class: u32,
            process_information: *const u32,
            process_information_length: u32,
        ) -> i32; // NTSTATUS
    }
    const PROCESS_BREAK_ON_TERMINATION: u32 = 29;

    if pid == 0 || pid == 4 {
        return Err("Невозможно изменить ядро системы".to_string());
    }
    unsafe {
        let h = OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
            false,
            pid,
        ).map_err(|e| format!("OpenProcess PID {pid}: {e}"))?;
        if h.is_invalid() {
            return Err(format!("Не удалось открыть процесс PID {pid}"));
        }
        let value: u32 = if critical { 1 } else { 0 };
        let status = NtSetInformationProcess(
            h.0,
            PROCESS_BREAK_ON_TERMINATION,
            &value,
            std::mem::size_of::<u32>() as u32,
        );
        let _ = CloseHandle(h);
        if status < 0 {
            Err(format!("NtSetInformationProcess: NTSTATUS 0x{:08X}. Возможно, требуются права администратора.", status as u32))
        } else {
            Ok(())
        }
    }
}

/// Проверить, является ли процесс критичным (ProcessBreakOnTermination).
#[tauri::command]
async fn query_process_critical(pid: u32) -> bool {
    tauri::async_runtime::spawn_blocking(move || query_critical_impl(pid))
        .await.unwrap_or(false)
}

fn query_critical_impl(pid: u32) -> bool {
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION},
    };

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process_handle: isize,
            process_information_class: u32,
            process_information: *mut u32,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }
    const PROCESS_BREAK_ON_TERMINATION: u32 = 29;

    if pid == 0 || pid == 4 { return false; }
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) else { return false; };
        if h.is_invalid() { return false; }
        let mut value: u32 = 0;
        let mut ret_len: u32 = 0;
        let status = NtQueryInformationProcess(
            h.0,
            PROCESS_BREAK_ON_TERMINATION,
            &mut value,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(h);
        status >= 0 && value != 0
    }
}

// ── Команды: DLL и скрытые процессы ──────────────────────────────────────────

#[tauri::command]
async fn get_process_dlls(pid: u32) -> Vec<DllInfo> {
    tauri::async_runtime::spawn_blocking(move || process::get_process_dlls(pid))
        .await.unwrap_or_default()
}

#[tauri::command]
async fn find_hidden_processes() -> Vec<HiddenProcess> {
    tauri::async_runtime::spawn_blocking(process::find_hidden_processes)
        .await.unwrap_or_default()
}

// ── Команды: сетевые соединения ───────────────────────────────────────────────

#[tauri::command]
async fn kill_tcp_connection(
    local_addr: String, local_port: u16,
    remote_addr: String, remote_port: u16,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        network::kill_tcp_connection(&local_addr, local_port, &remote_addr, remote_port)
    }).await.map_err(|e| e.to_string())?
}

// ── Команды: автозагрузка ─────────────────────────────────────────────────────

#[tauri::command]
async fn delete_startup_entry_cmd(name: String, hive: String, location: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || startup::delete_startup_entry(&name, &hive, &location))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn edit_startup_entry_cmd(name: String, hive: String, location: String, new_command: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || startup::edit_startup_entry(&name, &hive, &location, &new_command))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn open_file_location(path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || startup::open_file_location(&path))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn delete_file_at_path(path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || startup::delete_file_at_path(&path))
        .await.map_err(|e| e.to_string())?
}

// ── Команды: реестр / ограничения ─────────────────────────────────────────────

#[tauri::command]
async fn reg_check_value(hive: String, key: String, value_name: String) -> bool {
    tauri::async_runtime::spawn_blocking(move || recovery::reg_value_exists(&hive, &key, &value_name))
        .await.unwrap_or(false)
}

#[tauri::command]
async fn reg_read_dword_cmd(hive: String, key: String, value_name: String) -> i64 {
    tauri::async_runtime::spawn_blocking(move || recovery::reg_read_dword(&hive, &key, &value_name))
        .await.unwrap_or(-1)
}

#[tauri::command]
async fn reg_delete_value_cmd(hive: String, key: String, value_name: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || recovery::reg_delete_value(&hive, &key, &value_name))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn reg_set_dword_cmd(hive: String, key: String, value_name: String, data: u32) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || recovery::reg_set_dword(&hive, &key, &value_name, data))
        .await.map_err(|e| e.to_string())?
}

// ── Команды: терминал (потоковый) ─────────────────────────────────────────────


// ── Команды: форензика — SHA-256 и карантин ───────────────────────────────────

#[tauri::command]
async fn compute_sha256(path: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || forensics::compute_sha256(&path))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn quarantine_file_cmd(path: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || forensics::quarantine_file(&path))
        .await.map_err(|e| e.to_string())?
}

// ── Команды: восстановление системы ──────────────────────────────────────────

#[tauri::command]
async fn recovery_sfc() -> String {
    tauri::async_runtime::spawn_blocking(recovery::run_sfc).await.unwrap_or_default()
}

#[tauri::command]
async fn recovery_fix_mbr() -> String {
    tauri::async_runtime::spawn_blocking(recovery::fix_mbr).await.unwrap_or_default()
}

#[tauri::command]
async fn recovery_rebuild_bcd() -> String {
    tauri::async_runtime::spawn_blocking(recovery::rebuild_bcd).await.unwrap_or_default()
}

#[tauri::command]
async fn recovery_logonui() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(recovery::restore_logonui)
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn recovery_uac() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(recovery::enable_uac)
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn recovery_file_assoc() -> String {
    tauri::async_runtime::spawn_blocking(recovery::restore_file_associations)
        .await.unwrap_or_default()
}

#[tauri::command]
async fn recovery_keyboard() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(recovery::restore_keyboard)
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn recovery_mouse() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(recovery::restore_mouse)
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn recovery_fonts() -> String {
    tauri::async_runtime::spawn_blocking(recovery::restore_fonts).await.unwrap_or_default()
}

#[tauri::command]
async fn recovery_accessibility() -> String {
    tauri::async_runtime::spawn_blocking(recovery::restore_accessibility_tools)
        .await.unwrap_or_default()
}

// ── Команды: файловый менеджер ────────────────────────────────────────────────

#[tauri::command]
async fn fm_list_dir(path: String) -> Result<Vec<filemanager::FsEntry>, String> {
    tauri::async_runtime::spawn_blocking(move || filemanager::list_dir(&path))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fm_get_drives() -> Vec<filemanager::DriveInfo> {
    tauri::async_runtime::spawn_blocking(filemanager::get_drives)
        .await.unwrap_or_default()
}

#[tauri::command]
async fn fm_delete_path(path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || filemanager::delete_path(&path))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fm_create_dir(path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || filemanager::create_dir_at(&path))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fm_rename(src: String, new_name: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || filemanager::rename_path(&src, &new_name))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fm_copy(src: String, dst_dir: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || filemanager::copy_entry(&src, &dst_dir))
        .await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fm_move(src: String, dst_dir: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || filemanager::move_entry(&src, &dst_dir))
        .await.map_err(|e| e.to_string())?
}

// ── Команды: окно ────────────────────────────────────────────────────────────

#[tauri::command]
async fn set_always_on_top(window: tauri::Window, on_top: bool) -> Result<(), String> {
    window.set_always_on_top(on_top).map_err(|e| e.to_string())
}

#[tauri::command]
async fn export_report(path: String, content: String) -> Result<(), String> {
    std::fs::write(&path, content).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_app_dir() -> String {
    std::env::var("APPDATA")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| r"C:\Users".to_string())
}

#[tauri::command]
async fn open_browser_window(app: tauri::AppHandle, url: String) -> Result<(), String> {
    let label = format!("browser-{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());
    tauri::WindowBuilder::new(
        &app,
        label,
        tauri::WindowUrl::External(url.parse().map_err(|e: url::ParseError| e.to_string())?),
    )
    .title("FlowTrust Browser")
    .inner_size(1280.0, 800.0)
    .build()
    .map(|_| ())
    .map_err(|e: tauri::Error| e.to_string())
}

// ── Системный трей ────────────────────────────────────────────────────────────

fn build_tray() -> SystemTray {
    let show = CustomMenuItem::new("show".to_string(), "Открыть FlowTrust");
    let quit = CustomMenuItem::new("quit".to_string(), "Выход");
    let menu = SystemTrayMenu::new()
        .add_item(show)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit);
    SystemTray::new().with_menu(menu).with_tooltip("FlowTrust")
}

// ── Точка входа ───────────────────────────────────────────────────────────────

fn main() {
    security_check();

    tauri::Builder::default()
        .system_tray(build_tray())
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { .. } => {
                if let Some(win) = app.get_window("main") {
                    let _ = win.show(); let _ = win.set_focus();
                }
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "show" => {
                    if let Some(win) = app.get_window("main") {
                        let _ = win.show(); let _ = win.set_focus();
                    }
                }
                "quit" => std::process::exit(0),
                _ => {}
            },
            _ => {}
        })
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                api.prevent_close();
                let _ = event.window().hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            // Процессы
            get_processes, get_connections, get_startup, get_startup_full_cmd,
            get_threats, check_signature, kill_process,
            // Критичность процесса
            set_process_critical, query_process_critical,
            // DLL / руткит
            get_process_dlls, find_hidden_processes,
            // Сеть
            kill_tcp_connection,
            // Автозагрузка
            delete_startup_entry_cmd, edit_startup_entry_cmd,
            open_file_location, delete_file_at_path,
            // Реестр
            reg_check_value, reg_read_dword_cmd,
            reg_delete_value_cmd, reg_set_dword_cmd,
            // Форензика
            compute_sha256, quarantine_file_cmd,
            // Восстановление
            recovery_sfc, recovery_fix_mbr, recovery_rebuild_bcd,
            recovery_logonui, recovery_uac, recovery_file_assoc,
            recovery_keyboard, recovery_mouse, recovery_fonts,
            recovery_accessibility,
            // Файловый менеджер
            fm_list_dir, fm_get_drives, fm_delete_path,
            fm_create_dir, fm_rename, fm_copy, fm_move,
            // Окно
            set_always_on_top, export_report, open_browser_window, get_app_dir,
        ])
        .run(tauri::generate_context!())
        .expect("Ошибка запуска Tauri-приложения");
}
