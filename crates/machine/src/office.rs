//! Excel: is it running, which workbooks are open, and asking it to close. Genra only *asks*:
//! on Windows it posts WM_CLOSE to Excel's windows, on macOS it sends AppleScript `quit`
//! without `saving no`. Either way Excel itself asks the user to save. The process is never
//! killed.

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ExcelStatus {
    pub running: bool,
    /// Workbook names as Excel shows them ("Bao cao.xlsx"), when they can be read.
    pub open_documents: Vec<String>,
}

impl ExcelStatus {
    /// True when Excel has a workbook open whose name matches `file_name` (case-insensitive;
    /// a title shown without its extension matches too).
    pub fn has_open(&self, file_name: &str) -> bool {
        let f = file_name.to_lowercase();
        let stem = f.rsplit_once('.').map(|(s, _)| s.to_string()).unwrap_or_else(|| f.clone());
        self.open_documents.iter().map(|d| d.to_lowercase()).any(|d| d == f || d == stem)
    }
}

/// The workbook name in an Excel main-window title: "Book1.xlsx - Excel",
/// "Bao cao  [Compatibility Mode] - Excel", "Microsoft Excel - Book1.xls" (2010 and older).
/// `None` for a title with no workbook ("Excel", "Microsoft Excel").
pub fn workbook_from_title(title: &str) -> Option<String> {
    let t = title.trim();
    let t = if let Some(rest) = t.strip_prefix("Microsoft Excel - ") {
        rest
    } else if let Some((left, _)) = t.rsplit_once(" - Excel").filter(|(_, right)| right.trim().is_empty()) {
        left
    } else if let Some((left, _)) = t.rsplit_once(" - Microsoft Excel").filter(|(_, right)| right.trim().is_empty()) {
        left
    } else {
        return None;
    };
    // Drop markers Excel adds after the name: "[Compatibility Mode]", "[Chế độ Tương thích]",
    // "[Read-Only]", "[Group]"; and " - Saved"/"- Đã lưu" status words some builds add.
    let mut name = t.trim().to_string();
    while let Some(i) = name.rfind('[') {
        if name.ends_with(']') {
            name.truncate(i);
            name = name.trim_end().to_string();
        } else {
            break;
        }
    }
    for status in [" - Saved", " - Đã lưu", " - Saving…", " - AutoSave Off"] {
        if let Some(s) = name.strip_suffix(status) {
            name = s.trim_end().to_string();
        }
    }
    (!name.is_empty()).then_some(name)
}

/// Names from `osascript` output: "Book1.xlsx, Bao cao.xls".
pub fn parse_applescript_list(out: &str) -> Vec<String> {
    out.trim().split(", ").map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

pub fn excel_status() -> ExcelStatus {
    imp::excel_status()
}

/// Asks Excel to close. Returns once the request is sent; Excel may show its own "save?"
/// dialog, so call [`excel_status`] afterwards to see whether it closed.
pub fn ask_excel_to_close() -> Result<()> {
    imp::ask_excel_to_close()
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::proc::run;
    use std::time::Duration;

    const OSA: &str = "/usr/bin/osascript";
    const ID: &str = "com.microsoft.Excel";

    fn running() -> bool {
        // `is running` does not start the app.
        run(OSA, &["-e", &format!("application id \"{ID}\" is running")], Duration::from_secs(5)).is_ok_and(|o| o.stdout.trim() == "true")
    }

    pub fn excel_status() -> ExcelStatus {
        if !running() {
            return ExcelStatus::default();
        }
        // Guarded by `if running` inside the script too, so it can never launch Excel.
        let script = format!("if application id \"{ID}\" is running then tell application id \"{ID}\" to get name of every workbook");
        let open_documents = run(OSA, &["-e", &script], Duration::from_secs(8)).ok().filter(|o| o.ok()).map(|o| parse_applescript_list(&o.stdout)).unwrap_or_default();
        ExcelStatus { running: true, open_documents }
    }

    pub fn ask_excel_to_close() -> Result<()> {
        if !running() {
            return Ok(());
        }
        // No `saving no`: Excel asks the user about unsaved work. Not waiting for the reply,
        // so a "save?" dialog cannot hold us.
        let script = format!("if application id \"{ID}\" is running then\nignoring application responses\ntell application id \"{ID}\" to quit\nend ignoring\nend if");
        let o = run(OSA, &["-e", &script], Duration::from_secs(10))?;
        if !o.ok() {
            anyhow::bail!("Excel did not take the request: {}", o.stderr.trim());
        }
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::collections::HashSet;
    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{CloseHandle, HWND, INVALID_HANDLE_VALUE, LPARAM};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible, PostMessageW, WM_CLOSE,
    };

    fn excel_pids() -> HashSet<u32> {
        let mut out = HashSet::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let mut e: PROCESSENTRY32W = std::mem::zeroed();
            e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut e);
            while ok != 0 {
                let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
                let name = String::from_utf16_lossy(&e.szExeFile[..len]);
                if name.eq_ignore_ascii_case("excel.exe") {
                    out.insert(e.th32ProcessID);
                }
                ok = Process32NextW(snap, &mut e);
            }
            CloseHandle(snap);
        }
        out
    }

    struct Found {
        pids: HashSet<u32>,
        windows: Vec<(HWND, String)>,
    }

    unsafe extern "system" fn each(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let found = &mut *(lparam as *mut Found);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if !found.pids.contains(&pid) || IsWindowVisible(hwnd) == 0 {
            return 1;
        }
        let mut class = [0u16; 64];
        let n = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
        if String::from_utf16_lossy(&class[..n.max(0) as usize]) != "XLMAIN" {
            return 1;
        }
        let mut title = [0u16; 512];
        let n = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
        found.windows.push((hwnd, String::from_utf16_lossy(&title[..n.max(0) as usize])));
        1
    }

    fn main_windows() -> (bool, Vec<(HWND, String)>) {
        let pids = excel_pids();
        if pids.is_empty() {
            return (false, Vec::new());
        }
        let mut found = Found { pids, windows: Vec::new() };
        unsafe {
            EnumWindows(Some(each), &mut found as *mut Found as LPARAM);
        }
        (true, found.windows)
    }

    pub fn excel_status() -> ExcelStatus {
        let (running, windows) = main_windows();
        let mut open_documents: Vec<String> = windows.iter().filter_map(|(_, t)| workbook_from_title(t)).collect();
        open_documents.dedup();
        ExcelStatus { running, open_documents }
    }

    pub fn ask_excel_to_close() -> Result<()> {
        let (_, windows) = main_windows();
        for (hwnd, _) in windows {
            // The same message as the window's close button: Excel asks to save.
            unsafe {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            }
        }
        Ok(())
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use super::*;
    pub fn excel_status() -> ExcelStatus {
        ExcelStatus::default()
    }
    pub fn ask_excel_to_close() -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles() {
        assert_eq!(workbook_from_title("Book1.xlsx - Excel").as_deref(), Some("Book1.xlsx"));
        assert_eq!(workbook_from_title("Bao cao thang 11  [Compatibility Mode] - Excel").as_deref(), Some("Bao cao thang 11"));
        assert_eq!(workbook_from_title("BIỂU TỔNG HỢP.xls  [Chế độ Tương thích] - Excel").as_deref(), Some("BIỂU TỔNG HỢP.xls"));
        assert_eq!(workbook_from_title("Microsoft Excel - So lieu.xls").as_deref(), Some("So lieu.xls"));
        assert_eq!(workbook_from_title("a - b.xlsx - Excel").as_deref(), Some("a - b.xlsx"));
        assert_eq!(workbook_from_title("Book1.xlsx - Saved - Excel").as_deref(), Some("Book1.xlsx"));
        assert_eq!(workbook_from_title("Excel"), None);
        assert_eq!(workbook_from_title("Notes - Word"), None);
    }

    #[test]
    fn open_document_matching() {
        let s = ExcelStatus { running: true, open_documents: vec!["Bao cao".into(), "So lieu.XLS".into()] };
        assert!(s.has_open("bao cao.xls"));
        assert!(s.has_open("so lieu.xls"));
        assert!(!s.has_open("khac.xls"));
    }

    #[test]
    fn applescript_lists() {
        assert_eq!(parse_applescript_list("Book1.xlsx, Bao cao.xls\n"), ["Book1.xlsx", "Bao cao.xls"]);
        assert!(parse_applescript_list("\n").is_empty());
    }
}
