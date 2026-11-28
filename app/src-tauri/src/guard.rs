//! "Canh gác": the folders threats arrive in (Downloads, Zalo received files) are watched with the
//! OS's file notifications (no driver), each new or changed file is scanned once it has stopped
//! changing, and a USB stick is scanned when it is plugged in (J1, J8 in usability-audit.md).
//! Silent when clean; a find raises one notification and shows in the window.
//!
//! It runs inside the app while the app runs. Nothing is moved by the guard: the user decides
//! from the result screen, as for a file they checked themselves.

use crate::packs::Loaded;
use crate::ScanResult;
use genra_av_core::rules::Severity;
use notify::{EventKind, RecursiveMode, Watcher};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

/// A file is scanned once no event has touched it for this long (a download or a copy is done).
const QUIET: Duration = Duration::from_secs(2);
/// How often plugged-in drives and the watched folders are looked at again.
const LOOK_EVERY: Duration = Duration::from_secs(5);
/// Files above this are not read (as for a file checked by hand).
const MAX_FILE: u64 = 200 * 1024 * 1024;

/// Names a browser, Zalo or Office uses while a file is still being written, or for its own lock
/// files: never scanned (the finished file arrives under its real name).
fn partial(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("~$")
        || n.starts_with(".~lock")
        || [".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload"].iter().any(|e| n.ends_with(e))
}

/// Whether a path an event named is worth scanning: a type that can carry code, not a partial file.
pub fn worth(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return false };
    !partial(name) && (genra_av_core::targets::interesting(path) || genra_av_core::targets::in_startup_folder(path))
}

/// Paths waiting until they stop changing.
#[derive(Default)]
pub struct Settle {
    pending: HashMap<PathBuf, Instant>,
}

impl Settle {
    pub fn note(&mut self, path: PathBuf, now: Instant) {
        self.pending.insert(path, now);
    }

    /// Paths quiet for [`QUIET`], taken out of the list.
    pub fn ready(&mut self, now: Instant) -> Vec<PathBuf> {
        let done: Vec<PathBuf> = self.pending.iter().filter(|(_, t)| now.duration_since(**t) >= QUIET).map(|(p, _)| p.clone()).collect();
        for p in &done {
            self.pending.remove(p);
        }
        done
    }
}

/// How long one file (path and content) gives one notification: the same worm arriving again
/// later, or under another name, is told again.
const TELL_AGAIN: Duration = Duration::from_secs(600);
/// A folder moved or extracted into a watched place is walked this deep, this many files at most.
const FOLDER_DEPTH: usize = 4;
const FOLDER_FILES: usize = 2000;

/// Files already told about, by path and content, for [`TELL_AGAIN`].
#[derive(Default)]
pub struct Told {
    seen: HashMap<(String, String), Instant>,
}

impl Told {
    /// True the first time this path with this content is seen within [`TELL_AGAIN`].
    pub fn first(&mut self, path: &str, sha256: &str, now: Instant) -> bool {
        self.seen.retain(|_, at| now.duration_since(*at) < TELL_AGAIN);
        let key = (path.to_string(), sha256.to_ascii_lowercase());
        if self.seen.contains_key(&key) {
            return false;
        }
        self.seen.insert(key, now);
        true
    }
}

/// Files worth scanning under a folder that arrived whole (moved in, extracted): a watcher on
/// Windows reports the folder only, not each file in it.
pub fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            if out.len() >= FOLDER_FILES {
                return out;
            }
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() && !t.is_symlink() && depth < FOLDER_DEPTH && !genra_av_core::targets::skip_dir(&p) => stack.push((p, depth + 1)),
                Ok(t) if t.is_file() && worth(&p) => out.push(p),
                _ => {}
            }
        }
    }
    out
}

/// Where the guard looks, as the window shows it.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Status {
    pub on: bool,
    /// Folders watched now (Downloads, Zalo received files that exist).
    pub folders: Vec<String>,
    /// Removable drives plugged in now.
    pub usb: Vec<String>,
    /// A drive being scanned since it was plugged in.
    pub scanning: Option<String>,
}

/// The folders watched: Downloads and Zalo's received files, where they exist.
pub fn folders() -> Vec<PathBuf> {
    // Debug builds only: `GENRA_AV_GUARD_DIRS` (OS path list) replaces them, so end-to-end checks
    // never write into the real Downloads. Release builds do not contain this.
    #[cfg(debug_assertions)]
    if let Some(v) = std::env::var_os("GENRA_AV_GUARD_DIRS") {
        return std::env::split_paths(&v).filter(|p| p.is_dir()).collect();
    }
    crate::machine::guard_places()
        .into_iter()
        .filter(|g| g.kind != "usb")
        .flat_map(|g| g.paths)
        .map(PathBuf::from)
        .collect()
}

/// Scans one file the way a file checked by hand is scanned (without asking Defender, which
/// watches new files itself). `None` when it cannot be read or is too large.
fn scan_one(path: &Path, rules: &Loaded) -> Option<ScanResult> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let name = crate::util::file_name(path);
    let report = crate::quick::checked_quiet(genra_av_core::scan_named(&name, &bytes, Some(&rules.pack), Some(&rules.reputation)), path, rules);
    let hash_only = crate::quick::hash_only(&report);
    Some(ScanResult { name, path: path.to_string_lossy().into_owned(), size: meta.len(), hash_only, report })
}

fn is_hit(r: &ScanResult) -> bool {
    r.report.verdict.is_some_and(|v| v >= Severity::Suspicious)
}

/// The notification text, in the window's language.
fn notification(lang: &str, hit: &ScanResult, place: &str) -> (String, String) {
    let malware = hit.report.verdict == Some(Severity::Malware) && !hit.hash_only;
    if lang == "en" {
        let title = if malware { "Genra AV found malware" } else { "Genra AV found a suspicious file" };
        (title.into(), format!("{} in {place}. Open Genra AV to clean it or move it aside.", hit.name))
    } else {
        let title = if malware { "Genra AV tìm thấy mã độc" } else { "Genra AV thấy một tệp đáng ngờ" };
        (title.into(), format!("{} trong {place}. Mở Genra AV để dọn hoặc cách ly.", hit.name))
    }
}

/// The watched place a path is in, for the notification ("Downloads", "Zalo").
fn place_of(path: &Path) -> String {
    let s = path.to_string_lossy().to_ascii_lowercase();
    if s.contains("zalo received files") {
        "Zalo".into()
    } else if s.contains("downloads") {
        "Downloads".into()
    } else {
        path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }
}

fn usb_place(drive: &Path, lang: &str) -> String {
    let d = drive.to_string_lossy();
    if lang == "en" { format!("USB drive {d}") } else { format!("USB {d}") }
}

/// What the window hears when a drive scan starts and ends.
#[derive(Clone, Serialize)]
struct UsbScan {
    drive: String,
    done: bool,
    hits: usize,
}

/// One find: allowed for the window, kept in the history, notified once per path and content
/// within [`TELL_AGAIN`] (a file rewritten in place raises several events).
fn found(app: &AppHandle, hit: ScanResult, told: &mut Told, place: impl FnOnce(&str) -> String) {
    let st = app.state::<crate::AppState>();
    st.allow(Path::new(&hit.path));
    if !told.first(&hit.path, &hit.report.sha256, Instant::now()) {
        return;
    }
    let lang = st.lang();
    let (title, body) = notification(&lang, &hit, &place(&lang));
    {
        use tauri_plugin_notification::NotificationExt;
        let _ = app.notification().builder().title(title).body(body).show();
    }
    crate::record_check(app, &hit);
    let _ = app.emit("guard-hit", &hit);
}

/// Changes the status; the window hears about it only when something changed (it re-renders).
fn set_status(app: &AppHandle, f: impl FnOnce(&mut Status)) {
    let st = app.state::<crate::AppState>();
    let s = {
        let Ok(mut s) = st.guard.lock() else { return };
        let before = s.clone();
        f(&mut s);
        if *s == before {
            return;
        }
        s.clone()
    };
    let _ = app.emit("guard-status", s);
}

/// Drives being scanned now (two sticks plugged in together each get a scan).
static SCANNING: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn scanning_changed(app: &AppHandle, f: impl FnOnce(&mut Vec<String>)) {
    let first = {
        let Ok(mut v) = SCANNING.lock() else { return };
        f(&mut v);
        v.first().cloned()
    };
    set_status(app, |s| s.scanning = first);
}

/// Scans a drive that was just plugged in, on its own thread (a big stick takes a while).
fn scan_drive(app: &AppHandle, drive: PathBuf) {
    let a = app.clone();
    std::thread::spawn(move || {
        let label = drive.to_string_lossy().into_owned();
        scanning_changed(&a, |v| v.push(label.clone()));
        let _ = a.emit("guard-usb", UsbScan { drive: label.clone(), done: false, hits: 0 });
        let st = a.state::<crate::AppState>();
        let rules = st.rules();
        let mut walk = genra_av_core::scanner::Walk::quick();
        let hidden = [drive.clone()];
        walk.hidden_ok = &hidden;
        walk.max_depth = genra_av_core::scanner::DEEP;
        let roots = [drive.clone()];
        let job = crate::quick::Job { scope: "usb", roots: &roots, walk };
        let result = crate::quick::run_job(&st.data, &rules, &job, |_| {});
        let n = result.hits.len();
        let mut told = Told::default();
        for h in result.hits {
            found(&a, h, &mut told, |lang| usb_place(&drive, lang));
        }
        scanning_changed(&a, |v| v.retain(|d| d != &label));
        let _ = a.emit("guard-usb", UsbScan { drive: label, done: true, hits: n });
    });
}

/// Starts the guard thread. It follows the `guard_on` flag: off drops the watcher, on makes a
/// new one. Drives plugged in when the guard starts are not scanned (the quick scan covers them).
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher: Option<notify::RecommendedWatcher> = None;
        // The folders asked for last time, and the ones actually watched (a folder may refuse).
        let mut asked: Vec<PathBuf> = Vec::new();
        let mut watched: Vec<PathBuf> = Vec::new();
        let mut settle = Settle::default();
        let mut told = Told::default();
        let mut drives: Option<Vec<PathBuf>> = None;
        let mut last_look = Instant::now() - LOOK_EVERY;
        loop {
            let on = app.state::<crate::AppState>().guard_on.load(Ordering::SeqCst);
            if !on {
                if watcher.take().is_some() || drives.is_some() {
                    watched.clear();
                    asked.clear();
                    drives = None;
                    set_status(&app, |s| *s = Status::default());
                }
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            if last_look.elapsed() >= LOOK_EVERY {
                last_look = Instant::now();
                // Folders: (re)watch when the set changed (Zalo installed later, for example).
                let want = folders();
                if watcher.is_none() || want != asked {
                    let t = tx.clone();
                    watcher = notify::recommended_watcher(move |e| {
                        let _ = t.send(e);
                    })
                    .ok();
                    watched.clear();
                    if let Some(w) = watcher.as_mut() {
                        for d in &want {
                            if w.watch(d, RecursiveMode::Recursive).is_ok() {
                                watched.push(d.clone());
                            }
                        }
                    }
                    asked = want;
                }
                // Drives: scan the ones that appeared since the last look.
                let now = genra_av_core::targets::removable_volumes();
                if let Some(before) = &drives {
                    for d in now.iter().filter(|d| !before.contains(d)) {
                        scan_drive(&app, d.clone());
                    }
                }
                drives = Some(now.clone());
                let folders: Vec<String> = watched.iter().map(|p| p.to_string_lossy().into_owned()).collect();
                let usb: Vec<String> = now.iter().map(|p| p.to_string_lossy().into_owned()).collect();
                set_status(&app, |s| {
                    s.on = true;
                    s.folders = folders;
                    s.usb = usb;
                });
            }
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(Ok(ev)) => {
                    if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                        for p in ev.paths {
                            if p.is_dir() {
                                // A folder moved or extracted in arrives as one event.
                                if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(notify::event::ModifyKind::Name(_))) {
                                    for f in files_in(&p) {
                                        settle.note(f, Instant::now());
                                    }
                                }
                            } else if worth(&p) {
                                settle.note(p, Instant::now());
                            }
                        }
                    }
                }
                Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            let ready = settle.ready(Instant::now());
            if ready.is_empty() {
                continue;
            }
            let rules = app.state::<crate::AppState>().rules();
            for p in ready {
                if let Some(r) = scan_one(&p, &rules).filter(is_hit) {
                    let place = place_of(Path::new(&r.path));
                    found(&app, r, &mut told, |_| place);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_downloads_and_lock_files_wait() {
        assert!(!worth(Path::new("/u/Downloads/bao_cao.xls.crdownload")));
        assert!(!worth(Path::new("/u/Downloads/~$bao_cao.xlsx")));
        assert!(!worth(Path::new("/u/Downloads/hop_dong.docx.part")));
        assert!(worth(Path::new("/u/Downloads/bao_cao.xls")));
        assert!(!worth(Path::new("/u/Downloads/anh.jpg")), "types that carry no code are left out");
    }

    #[test]
    fn settle_waits_for_quiet() {
        let t0 = Instant::now();
        let mut s = Settle::default();
        s.note(PathBuf::from("a.xls"), t0);
        assert!(s.ready(t0 + Duration::from_secs(1)).is_empty());
        s.note(PathBuf::from("a.xls"), t0 + Duration::from_secs(1));
        assert!(s.ready(t0 + Duration::from_secs(2)).is_empty(), "a new event restarts the wait");
        assert_eq!(s.ready(t0 + Duration::from_secs(3)), vec![PathBuf::from("a.xls")]);
        assert!(s.pending.is_empty());
    }

    #[test]
    fn places_in_notifications() {
        assert_eq!(place_of(Path::new("/Users/lan/Downloads/a.xls")), "Downloads");
        assert_eq!(place_of(Path::new("/Users/lan/Documents/Zalo Received Files/a.xls")), "Zalo");
        assert_eq!(usb_place(Path::new("E:\\"), "vi"), "USB E:\\");
        assert_eq!(usb_place(Path::new("/Volumes/KINGSTON"), "en"), "USB drive /Volumes/KINGSTON");
    }

    #[test]
    fn told_once_per_path_and_content_for_a_while() {
        let t0 = Instant::now();
        let mut t = Told::default();
        assert!(t.first("/d/a.xls", "AB", t0));
        assert!(!t.first("/d/a.xls", "ab", t0 + Duration::from_secs(5)), "same file rewritten");
        assert!(t.first("/d/a (1).xls", "ab", t0 + Duration::from_secs(5)), "same worm, another name");
        assert!(t.first("/d/a.xls", "ab", t0 + TELL_AGAIN + Duration::from_secs(1)), "arrives again later");
    }

    #[test]
    fn a_folder_that_arrives_whole_is_walked() {
        let dir = std::env::temp_dir().join(format!("genra-guard-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("giai_nen/sub")).unwrap();
        std::fs::write(dir.join("giai_nen/bao_cao.xlsm"), b"x").unwrap();
        std::fs::write(dir.join("giai_nen/sub/hoadon.js"), b"x").unwrap();
        std::fs::write(dir.join("giai_nen/anh.jpg"), b"x").unwrap();
        let mut got = files_in(&dir.join("giai_nen"));
        got.sort();
        assert_eq!(got, vec![dir.join("giai_nen/bao_cao.xlsm"), dir.join("giai_nen/sub/hoadon.js")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scans_a_file_and_finds_nothing_in_a_clean_one() {
        let dir = std::env::temp_dir().join(format!("genra-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.docx");
        std::fs::write(&f, b"not really a docx").unwrap();
        let r = scan_one(&f, &crate::packs::bundled()).expect("read");
        assert!(!is_hit(&r));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
