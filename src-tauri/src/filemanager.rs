// Модуль файлового менеджера — работает напрямую через API файловой системы,
// независимо от explorer.exe. Поддерживает скрытые/системные файлы.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Типы ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct FsEntry {
    pub name:      String,
    pub path:      String,
    pub is_dir:    bool,
    pub size:      u64,
    pub modified:  String,  // ISO-like строка
    pub readonly:  bool,
    pub hidden:    bool,
    pub system:    bool,
    pub ext:       String,
}

#[derive(Debug, Serialize, Clone)]
pub struct DriveInfo {
    pub letter: String,   // "C:", "D:", ...
    pub label:  String,
    pub total:  u64,
    pub free:   u64,
}

// ── Утилиты ───────────────────────────────────────────────────────────────────

fn systime_to_str(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    // Простое преобразование секунд в дату (без внешних зависимостей)
    // Точность ±1 день достаточна для файлового менеджера
    let s   = secs % 60;
    let m   = (secs / 60) % 60;
    let h   = (secs / 3600) % 24;
    let day_of_epoch = secs / 86400;
    // Дата от 1970-01-01
    let (year, month, day) = epoch_days_to_ymd(day_of_epoch);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, h, m, s)
}

fn epoch_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Алгоритм Хоффмана для конверсии дней с эпохи в дату
    days += 719468;
    let era = days / 146097;
    let doe = days % 146097;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let y   = yoe + era * 400;
    let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp  = (5*doy + 2) / 153;
    let d   = doy - (153*mp + 2)/5 + 1;
    let mo  = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr  = if mo <= 2 { y + 1 } else { y };
    (yr, mo, d)
}

fn format_size(n: u64) -> String {
    if n < 1024 {
        format!("{} B", n)
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// ── Основные операции ─────────────────────────────────────────────────────────

/// Перечислить содержимое директории. Включает скрытые/системные файлы.
pub fn list_dir(path: &str) -> Result<Vec<FsEntry>, String> {
    let dir_path = Path::new(path);
    let read_dir = std::fs::read_dir(dir_path)
        .map_err(|e| format!("Нет доступа к «{path}»: {e}"))?;

    let mut entries: Vec<FsEntry> = read_dir
        .filter_map(|res| {
            let entry = res.ok()?;
            let meta  = entry.metadata().ok()?;
            let name  = entry.file_name().to_string_lossy().to_string();
            let full  = entry.path().to_string_lossy().to_string();
            let is_dir = meta.is_dir();
            let size   = if is_dir { 0 } else { meta.len() };
            let ext    = if is_dir {
                String::new()
            } else {
                Path::new(&name)
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
                    .unwrap_or_default()
            };
            let modified = meta.modified()
                .map(|t| systime_to_str(t))
                .unwrap_or_else(|_| "—".to_string());

            #[cfg(windows)]
            let (readonly, hidden, system) = {
                use std::os::windows::fs::MetadataExt;
                let attrs = meta.file_attributes();
                (
                    attrs & 0x1  != 0, // FILE_ATTRIBUTE_READONLY
                    attrs & 0x2  != 0, // FILE_ATTRIBUTE_HIDDEN
                    attrs & 0x4  != 0, // FILE_ATTRIBUTE_SYSTEM
                )
            };
            #[cfg(not(windows))]
            let (readonly, hidden, system) = (false, false, false);

            Some(FsEntry { name, path: full, is_dir, size, modified, readonly, hidden, system, ext })
        })
        .collect();

    // Сортировка: папки → файлы, внутри по имени
    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir)
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(entries)
}

/// Получить список логических дисков с метаданными (метка, размер).
pub fn get_drives() -> Vec<DriveInfo> {
    #[cfg(windows)]
    {
        use windows::Win32::Storage::FileSystem::{
            GetLogicalDrives, GetDiskFreeSpaceExW, GetVolumeInformationW,
        };
        use windows::core::PCWSTR;

        unsafe {
            let mask = GetLogicalDrives();
            let mut drives = Vec::new();

            for bit in 0u32..26 {
                if mask & (1 << bit) == 0 { continue; }
                let letter = char::from(b'A' + bit as u8);
                let path_str = format!("{}:\\", letter);
                let wide: Vec<u16> = path_str.encode_utf16().chain(Some(0)).collect();

                // Метка тома
                let mut label_buf = vec![0u16; 256];
                let _ = GetVolumeInformationW(
                    PCWSTR(wide.as_ptr()),
                    Some(&mut label_buf),
                    None, None, None, None,
                );
                let label_end = label_buf.iter().position(|&c| c == 0).unwrap_or(0);
                let label = String::from_utf16_lossy(&label_buf[..label_end]);

                // Свободное / всего место
                let mut free_bytes  = 0u64;
                let mut total_bytes = 0u64;
                let _ = GetDiskFreeSpaceExW(
                    PCWSTR(wide.as_ptr()),
                    None,
                    Some(&mut total_bytes),
                    Some(&mut free_bytes),
                );

                drives.push(DriveInfo {
                    letter: format!("{}:", letter),
                    label,
                    total: total_bytes,
                    free:  free_bytes,
                });
            }
            drives
        }
    }
    #[cfg(not(windows))]
    { vec![] }
}

/// Удалить файл или директорию (рекурсивно для папок).
pub fn delete_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if !p.exists() { return Err(format!("Путь не существует: {path}")); }
    if p.is_dir() {
        std::fs::remove_dir_all(p).map_err(|e| format!("Ошибка удаления директории: {e}"))
    } else {
        // Снимаем атрибут readonly перед удалением
        #[cfg(windows)]
        {
            use windows::Win32::Storage::FileSystem::{
                SetFileAttributesW, FILE_ATTRIBUTE_NORMAL,
            };
            use windows::core::PCWSTR;
            unsafe {
                let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
                let _ = SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_ATTRIBUTE_NORMAL);
            }
        }
        std::fs::remove_file(p).map_err(|e| format!("Ошибка удаления файла: {e}"))
    }
}

/// Создать директорию по указанному пути (включая промежуточные).
pub fn create_dir_at(path: &str) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("Ошибка создания директории: {e}"))
}

/// Переименовать файл или папку (только в пределах одного тома).
pub fn rename_path(src: &str, new_name: &str) -> Result<String, String> {
    let src_path  = Path::new(src);
    let parent    = src_path.parent().ok_or("Нет родительской директории")?;
    let new_path  = parent.join(new_name);
    std::fs::rename(src_path, &new_path)
        .map_err(|e| format!("Ошибка переименования: {e}"))?;
    Ok(new_path.to_string_lossy().to_string())
}

/// Копировать файл или директорию в целевую папку.
pub fn copy_entry(src: &str, dst_dir: &str) -> Result<String, String> {
    let src_path = Path::new(src);
    let name     = src_path.file_name().ok_or("Нет имени файла")?;
    let dst_path = PathBuf::from(dst_dir).join(name);

    if src_path.is_dir() {
        copy_dir_all(src_path, &dst_path)
            .map_err(|e| format!("Ошибка копирования директории: {e}"))?;
    } else {
        std::fs::copy(src_path, &dst_path)
            .map_err(|e| format!("Ошибка копирования файла: {e}"))?;
    }
    Ok(dst_path.to_string_lossy().to_string())
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let t = entry.file_type()?;
        let dst_child = dst.join(entry.file_name());
        if t.is_dir() {
            copy_dir_all(&entry.path(), &dst_child)?;
        } else {
            std::fs::copy(entry.path(), &dst_child)?;
        }
    }
    Ok(())
}

/// Переместить файл или директорию в целевую папку.
pub fn move_entry(src: &str, dst_dir: &str) -> Result<String, String> {
    let src_path = Path::new(src);
    let name     = src_path.file_name().ok_or("Нет имени файла")?;
    let dst_path = PathBuf::from(dst_dir).join(name);

    std::fs::rename(src_path, &dst_path)
        .map_err(|e| format!("Ошибка перемещения: {e}"))?;
    Ok(dst_path.to_string_lossy().to_string())
}
