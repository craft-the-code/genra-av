//! Genra AV desktop app. The window only asks; the Rust side reads files, runs the core scanner,
//! cleans and quarantines, and keeps the rule pack current. Nothing leaves the machine except an
//! explicit "báo nhầm" report, or a detected file's hash when the user turned that on (Q8).

mod allow;
mod history;
pub mod machine;
mod packs;
mod quick;
mod repair;
mod settings;
mod util;

use allow::Allow;
use genra_av_core::rules::{trusted_keys, Severity};
use history::{Entry, History, Kind, Undo};
use machine::Machine;
use packs::Loaded;
use serde::Serialize;
use settings::Settings;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

/// Files above this are not read: Office documents worth scanning are far smaller (same cap as the CLI).
const MAX_FILE: u64 = 200 * 1024 * 1024;
const REPORT_URL: &str = "https://genra-api.craftthecode.dev/v1/report";
const MAX_NOTE: usize = 2000;

struct AppState {
    data: PathBuf,
    rules: RwLock<Arc<Loaded>>,
    status: Mutex<packs::Status>,
    allow: Mutex<Allow>,
    history: Mutex<History>,
    settings: Mutex<Settings>,
    quick_running: AtomicBool,
    machine: Box<dyn Machine>,
}

impl AppState {
    fn rules(&self) -> Arc<Loaded> {
        self.rules.read().map(|r| r.clone()).unwrap_or_else(|p| p.into_inner().clone())
    }
    fn allowed(&self, path: &str) -> Result<PathBuf, String> {
        self.allow.lock().map_err(|e| e.to_string())?.check(path)
    }
    fn allow(&self, p: &Path) {
        if let Ok(mut a) = self.allow.lock() {
            a.add(p);
        }
    }
    fn record(&self, e: Entry) {
        if let Ok(mut h) = self.history.lock() {
            let _ = h.push(e);
        }
    }
}

type St<'a> = State<'a, AppState>;

fn failure(code: &'static str, detail: impl std::fmt::Display) -> repair::Failure {
    repair::Failure { kind: "failed", code, detail: detail.to_string() }
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    name: String,
    path: String,
    size: u64,
    /// Only a public hash feed matched: shown as "Đáng ngờ", never moved automatically.
    hash_only: bool,
    report: genra_av_core::Report,
}

#[derive(Serialize)]
struct RulesInfo {
    version: u64,
    published: String,
    rules: usize,
    hashes: usize,
    source: packs::Source,
    expires: Option<i64>,
    last_ok: Option<i64>,
    last_try: Option<i64>,
    last_error: Option<String>,
}

#[tauri::command]
fn rules_info(st: St) -> RulesInfo {
    let r = st.rules();
    let s = st.status.lock().map(|s| s.clone()).unwrap_or_default();
    RulesInfo {
        version: r.pack.version,
        published: r.pack.published.clone(),
        rules: r.pack.rules.len(),
        hashes: r.reputation.entries(),
        source: r.source,
        expires: r.pack.expires.map(|e| e.0),
        last_ok: s.last_ok,
        last_try: s.last_try,
        last_error: s.last_error,
    }
}

/// A file passed on the command line (`genra-av-app <file>`, later "Open with Genra AV").
#[tauri::command]
fn launch_path(st: St) -> Option<String> {
    let p = std::env::args_os().skip(1).map(PathBuf::from).find(|p| p.is_file())?;
    st.allow(&p);
    Some(p.to_string_lossy().into_owned())
}

/// The open dialog runs here, not in the window, so the picked path joins the allowlist.
#[tauri::command]
async fn pick_file(app: AppHandle) -> Result<Option<String>, String> {
    let a = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || a.dialog().file().blocking_pick_file()).await.map_err(|e| e.to_string())?;
    let Some(path) = picked.and_then(|f| f.into_path().ok()) else { return Ok(None) };
    app.state::<AppState>().allow(&path);
    Ok(Some(path.to_string_lossy().into_owned()))
}

/// Reads the file (never opens or runs it) and scans it with the installed pack and hash lists.
#[tauri::command]
async fn scan_file(app: AppHandle, path: String) -> Result<ScanResult, String> {
    let st = app.state::<AppState>();
    let p = st.allowed(&path)?;
    let rules = st.rules();
    let result = tauri::async_runtime::spawn_blocking(move || -> Result<ScanResult, String> {
        let meta = std::fs::metadata(&p).map_err(|e| format!("read: {e}"))?;
        if !meta.is_file() {
            return Err("not_a_file".into());
        }
        if meta.len() > MAX_FILE {
            return Err("too_large".into());
        }
        let bytes = std::fs::read(&p).map_err(|e| format!("read: {e}"))?;
        let report = genra_av_core::scan_with(&bytes, Some(&rules.pack), Some(&rules.reputation));
        Ok(ScanResult { name: util::file_name(&p), path, size: meta.len(), hash_only: quick::hash_only(&report), report })
    })
    .await
    .map_err(|e| e.to_string())??;
    let top = result.report.findings.iter().max_by_key(|f| f.severity);
    st.record(Entry {
        id: util::new_id(),
        at: util::now(),
        kind: Kind::Check,
        name: result.name.clone(),
        path: Some(result.path.clone()),
        verdict: result.report.verdict.filter(|v| *v >= Severity::Suspicious),
        family: top.map(|f| f.family.clone()),
        files: None,
        hits: None,
        undo: None,
        undone: false,
    });
    if result.report.verdict.is_some_and(|v| v >= Severity::Suspicious) {
        send_detection(&app, &result.report.sha256, top.map(|f| f.rule.clone()));
    }
    Ok(result)
}

#[derive(Serialize)]
struct RepairDone {
    #[serde(flatten)]
    done: repair::Done,
    /// What the machine-level plan did, once the `machine` crate provides one.
    machine: Option<machine::PlanOutcome>,
}

/// "Dọn sạch giúp tôi". Asks the machine seam for a plan first (worm in Excel's startup folder,
/// other infected files); this build has none, so it does the file-level repair only.
#[tauri::command]
async fn repair_file(app: AppHandle, path: String) -> Result<RepairDone, repair::Failure> {
    let st = app.state::<AppState>();
    let p = st.allowed(&path).map_err(|e| failure("not_allowed", e))?;
    let rules = st.rules();
    let data = st.data.clone();
    let a = app.clone();
    let out = tauri::async_runtime::spawn_blocking(move || {
        let st = a.state::<AppState>();
        let machine = std::fs::read(&p)
            .ok()
            .map(|b| genra_av_core::scan_with(&b, Some(&rules.pack), Some(&rules.reputation)))
            .and_then(|r| st.machine.plan_for_threat(&r, &p).ok())
            .and_then(|plan| st.machine.run_plan(&plan).ok());
        repair::run(&data, &rules, &p).map(|done| RepairDone { done, machine })
    })
    .await
    .map_err(|e| failure("other", e))??;
    st.allow(Path::new(&out.done.clean_path));
    st.record(Entry {
        id: util::new_id(),
        at: util::now(),
        kind: Kind::Repair,
        name: out.done.name.clone(),
        path: Some(out.done.clean_path.clone()),
        verdict: None,
        family: Some(out.done.family.clone()),
        files: None,
        hits: None,
        undo: Some(Undo::Repair { id: out.done.id.clone() }),
        undone: false,
    });
    Ok(out)
}

#[derive(Serialize)]
struct Quarantined {
    id: String,
    name: String,
}

/// "Cách ly tệp này": moves the file into Genra's quarantine (restorable for 30 days).
#[tauri::command]
async fn quarantine_file(app: AppHandle, path: String) -> Result<Quarantined, repair::Failure> {
    let st = app.state::<AppState>();
    let p = st.allowed(&path).map_err(|e| failure("not_allowed", e))?;
    let rules = st.rules();
    let data = st.data.clone();
    let item = tauri::async_runtime::spawn_blocking(move || repair::quarantine_file(&data, &rules, &p))
        .await
        .map_err(|e| failure("other", e))??;
    let name = util::file_name(&item.original_path);
    st.record(Entry {
        id: util::new_id(),
        at: util::now(),
        kind: Kind::Quarantine,
        name: name.clone(),
        path: Some(item.original_path.to_string_lossy().into_owned()),
        verdict: None,
        family: Some(item.reason.clone()),
        files: None,
        hits: None,
        undo: Some(Undo::Quarantine { id: item.id.clone() }),
        undone: false,
    });
    Ok(Quarantined { id: item.id, name })
}

/// "Hoàn tác" / "Lấy lại": one press, for a repair or a quarantined file.
#[tauri::command]
async fn undo(app: AppHandle, undo: Undo) -> Result<String, repair::Failure> {
    let st = app.state::<AppState>();
    let data = st.data.clone();
    let u = undo.clone();
    let restored = tauri::async_runtime::spawn_blocking(move || match &u {
        Undo::Repair { id } => repair::undo(&data, id),
        Undo::Quarantine { id } => repair::quarantine(&data).and_then(|q| q.restore(id)).map_err(|e| failure("restore", format!("{e:#}"))),
    })
    .await
    .map_err(|e| failure("other", e))??;
    st.allow(&restored);
    if let Ok(mut h) = st.history.lock() {
        let _ = h.mark_undone(&undo);
    }
    Ok(restored.to_string_lossy().into_owned())
}

#[derive(Serialize)]
struct EntryView {
    #[serde(flatten)]
    entry: Entry,
    can_undo: bool,
}

#[derive(Serialize)]
struct HistoryView {
    entries: Vec<EntryView>,
    /// Quarantined files with no history entry (moved there by the command line, for example).
    other_quarantine: Vec<genra_av_core::quarantine::Item>,
}

#[tauri::command]
fn history(st: St) -> Result<HistoryView, String> {
    let items = repair::quarantine(&st.data).and_then(|q| q.list()).unwrap_or_default();
    let repairs: Vec<repair::Record> = std::fs::read_dir(st.data.join("repairs"))
        .map(|rd| rd.flatten().filter_map(|e| std::fs::read(e.path()).ok()).filter_map(|b| serde_json::from_slice(&b).ok()).collect())
        .unwrap_or_default();
    let h = st.history.lock().map_err(|e| e.to_string())?;
    let entries: Vec<EntryView> = h
        .entries
        .iter()
        .map(|e| {
            let can_undo = !e.undone
                && match &e.undo {
                    Some(Undo::Quarantine { id }) => items.iter().any(|i| &i.id == id),
                    Some(Undo::Repair { id }) => repairs.iter().any(|r| &r.id == id),
                    None => false,
                };
            EntryView { entry: e.clone(), can_undo }
        })
        .collect();
    let known: Vec<&str> = h
        .entries
        .iter()
        .filter_map(|e| match &e.undo {
            Some(Undo::Quarantine { id }) => Some(id.as_str()),
            _ => None,
        })
        .chain(repairs.iter().map(|r| r.quarantine_id.as_str()))
        .collect();
    let other_quarantine = items.into_iter().filter(|i| !known.contains(&i.id.as_str())).collect();
    Ok(HistoryView { entries, other_quarantine })
}

/// Starts the quick scan on a background thread; progress and the result arrive as events.
#[tauri::command]
fn quick_scan(app: AppHandle) -> Result<(), String> {
    let st = app.state::<AppState>();
    if st.quick_running.swap(true, Ordering::SeqCst) {
        return Err("busy".into());
    }
    let a = app.clone();
    std::thread::spawn(move || {
        let st = a.state::<AppState>();
        let mut roots = genra_av_core::targets::quick_targets();
        roots.extend(genra_av_core::targets::removable_volumes());
        let rules = st.rules();
        let result = quick::run(&st.data, &rules, &roots, |p| {
            let _ = a.emit("quick-progress", p);
        });
        for h in &result.hits {
            st.allow(Path::new(&h.path));
            let top = h.report.findings.iter().max_by_key(|f| f.severity);
            send_detection(&a, &h.report.sha256, top.map(|f| f.rule.clone()));
        }
        st.record(Entry {
            id: util::new_id(),
            at: result.at,
            kind: Kind::QuickScan,
            name: String::new(),
            path: None,
            verdict: result.hits.iter().filter_map(|h| h.report.verdict).max(),
            family: None,
            files: Some(result.files_seen),
            hits: Some(result.hits.len() as u64),
            undo: None,
            undone: false,
        });
        st.quick_running.store(false, Ordering::SeqCst);
        let _ = a.emit("quick-done", &result);
    });
    Ok(())
}

/// Shows the file in Finder / Explorer; the file itself is not opened.
#[tauri::command]
fn reveal(st: St, path: String) -> Result<(), String> {
    let p = st.allowed(&path)?;
    tauri_plugin_opener::reveal_item_in_dir(p).map_err(|e| e.to_string())
}

/// Opens one of Genra's own pages in the browser. The window names the page, never the URL.
#[tauri::command]
fn open_link(which: String) -> Result<(), String> {
    let url = match which.as_str() {
        "privacy" => "https://craftthecode.dev/genra/privacy",
        "terms" => "https://craftthecode.dev/genra/terms",
        "source" => "https://github.com/craft-the-code/genra-av",
        _ => return Err("unknown link".into()),
    };
    tauri_plugin_opener::open_url(url, None::<&str>).map_err(|e| e.to_string())
}

#[tauri::command]
fn machine_overview(st: St) -> machine::Overview {
    machine::overview(st.machine.as_ref())
}

#[tauri::command]
fn get_settings(st: St) -> Settings {
    st.settings.lock().map(|s| s.clone()).unwrap_or_default()
}

#[tauri::command]
fn set_send_hashes(st: St, on: bool) -> Result<Settings, String> {
    let mut s = st.settings.lock().map_err(|e| e.to_string())?;
    s.send_hashes = on;
    s.save(&st.data).map_err(|e| e.to_string())?;
    Ok(s.clone())
}

/// A random id per install, so the backend can rate-limit and group reports. It says nothing
/// about the user and is stored only in the data folder.
fn install_id(data: &Path) -> Result<String, String> {
    let file = data.join("install_id");
    if let Ok(s) = std::fs::read_to_string(&file) {
        if let Ok(id) = uuid::Uuid::parse_str(s.trim()) {
            return Ok(id.hyphenated().to_string());
        }
    }
    let id = uuid::Uuid::new_v4().hyphenated().to_string();
    std::fs::create_dir_all(data).map_err(|e| e.to_string())?;
    std::fs::write(&file, &id).map_err(|e| e.to_string())?;
    Ok(id)
}

fn os_name() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        _ => "linux",
    }
}

async fn post_report(data: &Path, kind: &str, sha256: &str, rule_id: Option<String>, note: Option<String>) -> Result<(), String> {
    let body = serde_json::json!({
        "kind": kind,
        "sha256": sha256.to_ascii_lowercase(),
        "rule_id": rule_id,
        "app_version": env!("CARGO_PKG_VERSION"),
        "os": os_name(),
        "install_id": install_id(data)?,
        "note": note,
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("genra-av-app/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client.post(REPORT_URL).json(&body).send().await.map_err(|e| format!("network: {e}"))?;
    let status = res.status();
    if status.is_success() {
        Ok(())
    } else {
        let text = res.text().await.unwrap_or_default();
        Err(format!("{status}: {}", text.chars().take(300).collect::<String>()))
    }
}

/// Q8 opt-in: the hash and rule id of a detected file, never the file. Does nothing when off.
// TODO(backend): a dedicated `detection` report kind; until then it is sent as `other`.
fn send_detection(app: &AppHandle, sha256: &str, rule_id: Option<String>) {
    let st = app.state::<AppState>();
    if !st.settings.lock().is_ok_and(|s| s.send_hashes) {
        return;
    }
    let data = st.data.clone();
    let sha = sha256.to_string();
    tauri::async_runtime::spawn(async move {
        let _ = post_report(&data, "other", &sha, rule_id, Some("detection".into())).await;
    });
}

/// "Tệp này an toàn, báo nhầm": sends the hash, the rule id and the user's note. Never the file.
#[tauri::command]
async fn report_false_positive(st: State<'_, AppState>, sha256: String, rule_id: Option<String>, note: Option<String>) -> Result<(), String> {
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid sha256".into());
    }
    let note = note.map(|n| n.trim().chars().take(MAX_NOTE).collect::<String>()).filter(|n| !n.is_empty());
    post_report(&st.data, "false_positive", &sha256, rule_id, note).await
}

/// One update attempt: on success swap the loaded rules; always record the outcome.
async fn update_once(app: &AppHandle) {
    let st = app.state::<AppState>();
    let data = st.data.clone();
    let now = util::now();
    let outcome = match packs::Http::new() {
        Ok(http) => packs::update(&data, &http, &trusted_keys(), now).await,
        Err(e) => Err(e),
    };
    let mut status = st.status.lock().map(|s| s.clone()).unwrap_or_default();
    status.last_try = Some(now);
    match outcome {
        Ok(o) => {
            status.last_ok = Some(now);
            status.last_error = None;
            if let packs::Outcome::Installed(_) = o {
                let d = data.clone();
                if let Ok(loaded) = tauri::async_runtime::spawn_blocking(move || packs::load(&d)).await {
                    if let Ok(mut r) = st.rules.write() {
                        *r = Arc::new(loaded);
                    }
                }
            }
        }
        Err(e) => status.last_error = Some(format!("{e:#}")),
    }
    let _ = packs::write_status(&data, &status);
    if let Ok(mut s) = st.status.lock() {
        *s = status;
    }
    let _ = app.emit("rules-changed", ());
}

/// Debug builds only: `GENRA_AV_E2E_SCRIPT=<file.js>` evaluates that script in the window once it
/// has loaded, so screenshots and end-to-end checks can press buttons without a mouse. Release
/// builds do not contain this.
#[cfg(debug_assertions)]
fn e2e_script(app: &AppHandle) {
    let Some(path) = std::env::var_os("GENRA_AV_E2E_SCRIPT") else { return };
    let Ok(js) = std::fs::read_to_string(path) else { return };
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.eval(&js);
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data = genra_av_core::paths::data_dir().or_else(|_| app.path().app_data_dir())?;
            std::fs::create_dir_all(&data)?;
            if let Ok(q) = repair::quarantine(&data) {
                let _ = q.purge_expired();
            }
            let state = AppState {
                rules: RwLock::new(Arc::new(packs::load(&data))),
                status: Mutex::new(packs::read_status(&data)),
                allow: Mutex::new(Allow::default()),
                history: Mutex::new(History::load(&data)),
                settings: Mutex::new(Settings::load(&data)),
                quick_running: AtomicBool::new(false),
                machine: Box::new(machine::Unavailable),
                data,
            };
            app.manage(state);
            #[cfg(debug_assertions)]
            e2e_script(app.handle());
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    update_once(&handle).await;
                    tokio::time::sleep(packs::UPDATE_EVERY).await;
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Dropped paths join the allowlist here, then the window is told to check them.
            if let tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event {
                let st = window.state::<AppState>();
                for p in paths {
                    st.allow(p);
                }
                let list: Vec<String> = paths.iter().map(|p| p.to_string_lossy().into_owned()).collect();
                let _ = window.emit("dropped", list);
            }
        })
        .invoke_handler(tauri::generate_handler![
            rules_info,
            launch_path,
            pick_file,
            scan_file,
            repair_file,
            quarantine_file,
            undo,
            history,
            quick_scan,
            reveal,
            open_link,
            machine_overview,
            get_settings,
            set_send_hashes,
            report_false_positive
        ])
        .run(tauri::generate_context!())
        .expect("error while running Genra AV");
}
