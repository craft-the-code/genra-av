//! Where threats arrive, and which files are worth reading. The quick scan walks only these
//! places, and only file types that can carry active content, so it stays fast and light.

use std::path::{Path, PathBuf};

/// Extensions that can carry code or hide it: Office, scripts, shortcuts, executables, archives,
/// disk images, PDF. Everything else is skipped by the quick scan.
const INTERESTING: &[&str] = &[
    "doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltm", "xla", "xlam",
    "ppt", "pptx", "pptm", "pps", "ppsm", "rtf", "pdf", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1",
    "bat", "cmd", "lnk", "url", "exe", "dll", "scr", "msi", "com", "cpl", "jar", "zip", "rar", "7z", "iso",
    "img", "vhd",
];

/// Folders that never hold user-received threats and are large: skipped while walking.
const SKIP_DIRS: &[&str] = &["node_modules", ".git", "$recycle.bin", "system volume information", "library"];

pub fn interesting(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| INTERESTING.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

pub fn skip_dir(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SKIP_DIRS.contains(&n.as_str()) || (n.starts_with('.') && n.len() > 1)
}

fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

/// Downloads, Desktop, Documents, Zalo's received-files folder, and (Windows) Excel's startup
/// folder, where macro worms persist. Only folders that exist are returned.
pub fn quick_targets() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(h) = home() {
        for sub in ["Downloads", "Desktop", "Documents", "Documents/Zalo Received Files", "Zalo Received Files"] {
            out.push(h.join(sub));
        }
    }
    out.extend(excel_startup_dirs());
    out.retain(|p| p.is_dir());
    out.dedup();
    out
}

/// Excel's per-user and per-install startup folders (XLSTART). Windows only.
pub fn excel_startup_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            out.push(PathBuf::from(appdata).join("Microsoft").join("Excel").join("XLSTART"));
        }
        for pf in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(base) = std::env::var_os(pf) {
                let office = PathBuf::from(base).join("Microsoft Office");
                for root in ["root\\Office16", "Office16", "Office15", "Office14", "Office12"] {
                    out.push(office.join(root).join("XLSTART"));
                }
            }
        }
    }
    out.retain(|p| p.is_dir());
    out
}

/// Removable drives currently mounted (USB sticks, SD cards).
pub fn removable_volumes() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        windows_removable()
    }
    #[cfg(target_os = "macos")]
    {
        // Everything under /Volumes except the system volume (a link to /).
        std::fs::read_dir("/Volumes")
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| std::fs::canonicalize(p).map(|c| c != Path::new("/")).unwrap_or(false))
                    .collect()
            })
            .unwrap_or_default()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let user = std::env::var("USER").unwrap_or_default();
        [format!("/media/{user}"), format!("/run/media/{user}")]
            .iter()
            .filter_map(|d| std::fs::read_dir(d).ok())
            .flat_map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()))
            .collect()
    }
}

#[cfg(windows)]
fn windows_removable() -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_REMOVABLE: u32 = 2;
    let mask = unsafe { GetLogicalDrives() };
    (0..26u32)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:\\", (b'A' + i as u8) as char))
        .filter(|root| {
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_REMOVABLE }
        })
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_files_that_can_carry_code() {
        for f in ["a.XLS", "b.xlsm", "c.lnk", "d.exe", "e.zip", "f.pdf"] {
            assert!(interesting(Path::new(f)), "{f}");
        }
        for f in ["photo.jpg", "notes.txt", "song.mp3", "noext"] {
            assert!(!interesting(Path::new(f)), "{f}");
        }
    }

    #[test]
    fn skips_heavy_and_hidden_dirs() {
        assert!(skip_dir("node_modules"));
        assert!(skip_dir(".cache"));
        assert!(!skip_dir("Zalo Received Files"));
    }
}
