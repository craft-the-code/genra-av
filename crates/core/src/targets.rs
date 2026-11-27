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
const SKIP_DIRS: &[&str] = &["node_modules", ".git", "$recycle.bin", "system volume information"];

/// Folders whose every file an Office app loads at start, whatever its name or extension
/// (Excel opens `XLSTART\PERSONAL` with no extension). Every file in them is scanned.
const STARTUP_DIRS: &[&str] = &["xlstart"];

pub fn interesting(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| INTERESTING.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// True when `path` sits in an Office startup folder (see `STARTUP_DIRS`), at any depth.
pub fn in_startup_folder(path: &Path) -> bool {
    path.parent()
        .into_iter()
        .flat_map(|p| p.components())
        .any(|c| c.as_os_str().to_str().is_some_and(|s| STARTUP_DIRS.contains(&s.to_ascii_lowercase().as_str())))
}

/// Folders the quick scan does not walk into: heavy tool folders, hidden folders (the Hidden
/// attribute on Windows, a leading dot on Unix), and on macOS only `~/Library` itself.
pub fn skip_dir(path: &Path) -> bool {
    skip_dir_in(path, false)
}

/// [`skip_dir`], walking hidden folders too when `hidden_ok`: on a USB stick, where worms hide
/// their copies in hidden folders and leave shortcuts in sight.
pub fn skip_dir_in(path: &Path, hidden_ok: bool) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return false };
    if skip_dir_name(name) || (!hidden_ok && is_hidden(path)) {
        return true;
    }
    cfg!(target_os = "macos") && home().is_some_and(|h| path == h.join("Library"))
}

fn skip_dir_name(name: &str) -> bool {
    SKIP_DIRS.contains(&name.to_ascii_lowercase().as_str())
}

#[cfg(windows)]
fn is_hidden(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0)
}

#[cfg(not(windows))]
fn is_hidden(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with('.') && n.len() > 1)
}

fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

/// Folders under the home folder the quick scan walks. Pictures and Videos are cheap to walk
/// (only files that can carry code are read) and are where phones and Zalo PC save what they get.
const QUICK_SUBDIRS: &[&str] = &[
    "Downloads",
    "Desktop",
    "Documents",
    "Pictures",
    "Videos",
    "Documents/Zalo Received Files",
    "Zalo Received Files",
];

/// Downloads, Desktop, Documents, Pictures, Videos (also their OneDrive copies on Windows, where
/// OneDrive often moves them), Zalo's received-files folder, and (Windows) Excel's startup folder,
/// where macro worms persist. Only folders that exist are returned; a folder inside another
/// listed one is walked once.
pub fn quick_targets() -> Vec<PathBuf> {
    let mut bases: Vec<PathBuf> = home().into_iter().collect();
    if cfg!(windows) {
        for var in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
            if let Some(p) = std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()) {
                bases.push(p);
            }
        }
    }
    let mut out = Vec::new();
    for b in &bases {
        out.extend(QUICK_SUBDIRS.iter().map(|sub| b.join(sub)));
    }
    out.extend(excel_startup_dirs());
    out.retain(|p| p.is_dir());
    outermost(out)
}

/// Drops duplicates and folders that sit inside another folder of the list, so nothing is
/// walked twice. Order is kept.
pub fn outermost(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for d in dirs {
        if out.iter().any(|o| d.starts_with(o)) {
            continue;
        }
        out.retain(|o| !o.starts_with(&d));
        out.push(d);
    }
    out
}

/// "Quét toàn bộ máy": every fixed drive on Windows (C:, D:, …); the home folder elsewhere,
/// since the rest of a Mac or Linux disk is the system. Removable drives are added by the caller.
pub fn full_scan_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        windows_drives(3) // DRIVE_FIXED
    }
    #[cfg(not(windows))]
    {
        home().into_iter().filter(|p| p.is_dir()).collect()
    }
}

/// Folders a whole-drive scan leaves out: Windows itself and installed programs. They are large,
/// hold signed system files rather than documents users receive, and reading every DLL in them
/// would make the scan many times slower. User data under `AppData` and `ProgramData` is kept.
pub fn full_scan_skip() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        for var in ["SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(p) = std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()) {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
    }
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
        // Volumes under /Volumes that diskutil reports as external, removable or ejectable. The
        // system volume (a link to /) and internal ones such as Recovery are not removable drives.
        std::fs::read_dir("/Volumes")
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| std::fs::canonicalize(p).map(|c| c != Path::new("/")).unwrap_or(false))
                    .filter(|p| macos_is_removable(p))
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

#[cfg(target_os = "macos")]
fn macos_is_removable(volume: &Path) -> bool {
    std::process::Command::new("/usr/sbin/diskutil")
        .arg("info")
        .arg(volume)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| diskutil_says_removable(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or(false)
}

/// Reads `diskutil info` text: a volume counts as removable when it is external, removable media
/// or ejectable. Internal fixed volumes (Recovery, Preboot, a second internal disk) do not.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn diskutil_says_removable(info: &str) -> bool {
    info.lines().any(|line| {
        let Some((key, value)) = line.split_once(':') else { return false };
        let (key, value) = (key.trim(), value.trim());
        (key == "Device Location" && value == "External")
            || (key == "Removable Media" && value == "Removable")
            || (key == "Ejectable" && value == "Yes")
    })
}

#[cfg(windows)]
fn windows_removable() -> Vec<PathBuf> {
    windows_drives(2) // DRIVE_REMOVABLE
}

/// Drive roots (`C:\`) whose `GetDriveTypeW` is `kind`.
#[cfg(windows)]
fn windows_drives(kind: u32) -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    let mask = unsafe { GetLogicalDrives() };
    (0..26u32)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| format!("{}:\\", (b'A' + i as u8) as char))
        .filter(|root| {
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { GetDriveTypeW(wide.as_ptr()) == kind }
        })
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_external_or_removable_volumes_count_as_usb() {
        let recovery = "   Device Location:           Internal\n   Removable Media:           Fixed\n   Ejectable:                 No\n";
        let stick = "   Device Location:           External\n   Removable Media:           Removable\n   Ejectable:                 Yes\n";
        let card = "   Removable Media:           Removable\n";
        assert!(!diskutil_says_removable(recovery));
        assert!(diskutil_says_removable(stick));
        assert!(diskutil_says_removable(card));
        assert!(!diskutil_says_removable(""));
    }

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
        assert!(skip_dir(Path::new("/x/node_modules")));
        assert!(!skip_dir(Path::new("/x/Zalo Received Files")));
        // A folder merely named "library" (a school's, an office's) is walked.
        assert!(!skip_dir(Path::new("/x/Library")));
        assert!(!skip_dir(Path::new("/x/library")));
    }

    #[cfg(unix)]
    #[test]
    fn hides_dot_folders_on_unix() {
        assert!(skip_dir(Path::new("/x/.cache")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn skips_only_the_home_library_on_macos() {
        let h = home().unwrap();
        assert!(skip_dir(&h.join("Library")));
        assert!(!skip_dir(&h.join("Documents").join("Library")));
    }

    #[test]
    fn every_file_in_xlstart_counts() {
        assert!(in_startup_folder(Path::new("/u/AppData/Roaming/Microsoft/Excel/XLSTART/PERSONAL")));
        assert!(in_startup_folder(Path::new("/u/Excel/xlstart/sub/book.dat")));
        assert!(!in_startup_folder(Path::new("/u/Downloads/PERSONAL")));
        assert!(!in_startup_folder(Path::new("/u/XLSTART")), "the folder itself is not inside it");
    }

    #[test]
    fn nested_and_repeated_folders_are_walked_once() {
        let dirs = vec![
            PathBuf::from("/h/Documents/Zalo Received Files"),
            PathBuf::from("/h/Downloads"),
            PathBuf::from("/h/Documents"),
            PathBuf::from("/h/Downloads"),
        ];
        assert_eq!(outermost(dirs), [PathBuf::from("/h/Downloads"), PathBuf::from("/h/Documents")]);
    }

    #[test]
    fn whole_computer_has_at_least_one_root() {
        assert!(!full_scan_roots().is_empty());
    }
}
