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
use history::{Entry, HitItem, History, Kind, Undo};
use machine::Machine;
use packs::Loaded;
use repair::RepairView;
use serde::Serialize;
use settings::Settings;
use std::collections::HashMap;
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
    /// Set by "Dừng"; the running scan stops before its next folder.
    quick_stop: AtomicBool,
    machine: Box<dyn Machine>,
    /// Plans waiting for Excel to close, by group id; run again as they are.
    pending: Mutex<HashMap<String, Pending>>,
    /// "Máy của bạn", read once per session (health checks and signatures take a few seconds).
    overview: Mutex<Option<Arc<machine::Overview>>>,
}

/// A repair plan that came back "close Excel first", with what the done screen needs.
struct Pending {
    plan: genra_av_machine::repair::Plan,
    name: String,
    family: String,
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
    /// The next visit to "Máy của bạn" reads the machine again (something was changed).
    fn invalidate_overview(&self) {
        if let Ok(mut o) = self.overview.lock() {
            *o = None;
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
        let report = quick::checked(genra_av_core::scan_named(&util::file_name(&p), &bytes, Some(&rules.pack), Some(&rules.reputation)), &p, &rules);
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
        stopped: false,
        folders: 0,
        items: Vec::new(),
    });
    if result.report.verdict.is_some_and(|v| v >= Severity::Suspicious) {
        send_detection(&app, &result.report.sha256, top.map(|f| f.rule.clone()));
    }
    Ok(result)
}

/// What the window hears while a repair runs: `planning` while Genra looks for the worm and
/// other infected files, then each step as it starts and ends.
#[derive(Clone, Serialize)]
struct RepairProgress {
    phase: &'static str,
    step: Option<genra_av_machine::repair::StepProgress>,
}

/// Runs a plan, records a finished repair in the history, keeps a plan that waits for Excel.
fn execute(app: &AppHandle, plan: genra_av_machine::repair::Plan, name: String, family: String) -> Result<RepairView, repair::Failure> {
    let st = app.state::<AppState>();
    let a = app.clone();
    let report = st
        .machine
        .run_plan(&plan, &mut |p| {
            let _ = a.emit("repair-progress", RepairProgress { phase: "step", step: Some(p) });
        })
        .map_err(|e| failure("other", e))?;
    let view = repair::view(&plan, &name, &family, report);
    match &view {
        RepairView::Done { group_id, cleaned, .. } => {
            for p in repair::clean_paths(&view) {
                st.allow(&p);
            }
            st.record(Entry {
                id: util::new_id(),
                at: util::now(),
                kind: Kind::Repair,
                name: name.clone(),
                path: cleaned.first().map(|c| c.clean_path.clone()),
                verdict: None,
                family: Some(family.clone()),
                files: Some(plan.steps.len() as u64),
                hits: None,
                undo: Some(Undo::Group { id: group_id.clone() }),
                undone: false,
                stopped: false,
                folders: 0,
                items: Vec::new(),
            });
            st.invalidate_overview();
        }
        RepairView::NeedsExcel { group_id, .. } => {
            if let Ok(mut p) = st.pending.lock() {
                p.insert(group_id.clone(), Pending { plan, name, family });
            }
        }
        RepairView::NotDone { .. } => {}
    }
    Ok(view)
}

/// "Dọn sạch giúp tôi": cleans the file, takes the worm out of Excel's startup folder and cleans
/// the other infected workbooks, as one journal group ("Hoàn tác" undoes it all). Refused by the
/// cleaner: nothing changes and the window offers "Cách ly tệp này".
#[tauri::command]
async fn repair_file(app: AppHandle, path: String) -> Result<RepairView, repair::Failure> {
    let st = app.state::<AppState>();
    let p = st.allowed(&path).map_err(|e| failure("not_allowed", e))?;
    let rules = st.rules();
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _ = a.emit("repair-progress", RepairProgress { phase: "planning", step: None });
        let report = repair::precheck(&rules, &p)?;
        let st = a.state::<AppState>();
        let mut plan = st.machine.plan_for_threat(&p, &report, &rules);
        repair::keep_cleanable(&mut plan);
        execute(&a, plan, util::file_name(&p), repair::family_of(&report))
    })
    .await
    .map_err(|e| failure("other", e))?
}

/// Runs a plan that waited for Excel again, as it was. Called by the window once Excel is gone.
#[tauri::command]
async fn continue_repair(app: AppHandle, group_id: String) -> Result<RepairView, repair::Failure> {
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let st = a.state::<AppState>();
        let pending = st.pending.lock().ok().and_then(|mut p| p.remove(&group_id)).ok_or_else(|| failure("not_found", "no repair is waiting"))?;
        execute(&a, pending.plan, pending.name, pending.family)
    })
    .await
    .map_err(|e| failure("other", e))?
}

/// Polled every second while a repair waits for Excel.
#[tauri::command]
async fn excel_status(app: AppHandle) -> Result<machine::ExcelStatus, String> {
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || a.state::<AppState>().machine.excel_status()).await.map_err(|e| e.to_string())
}

/// "Đóng Excel giúp tôi": asks Excel to quit; Excel itself asks the user to save. Never killed.
#[tauri::command]
async fn close_excel(app: AppHandle) -> Result<(), String> {
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || a.state::<AppState>().machine.ask_excel_to_close()).await.map_err(|e| e.to_string())?
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
        stopped: false,
        folders: 0,
        items: Vec::new(),
    });
    Ok(Quarantined { id: item.id, name })
}

/// "Hoàn tác" / "Lấy lại": one press, for a whole journal group or a quarantined file.
#[tauri::command]
async fn undo(app: AppHandle, undo: Undo) -> Result<Vec<String>, repair::Failure> {
    let st = app.state::<AppState>();
    let data = st.data.clone();
    let u = undo.clone();
    let a = app.clone();
    let restored = tauri::async_runtime::spawn_blocking(move || match &u {
        Undo::Group { id } => a.state::<AppState>().machine.undo_group(id).map(|(_, back)| back).map_err(|e| failure("undo", e)),
        Undo::Quarantine { id } => repair::quarantine(&data).and_then(|q| q.restore(id)).map(|p| vec![p]).map_err(|e| failure("restore", format!("{e:#}"))),
    })
    .await
    .map_err(|e| failure("other", e))??;
    for p in &restored {
        st.allow(p);
    }
    if let Ok(mut h) = st.history.lock() {
        let _ = h.mark_undone(&undo);
    }
    st.invalidate_overview();
    Ok(restored.iter().map(|p| p.to_string_lossy().into_owned()).collect())
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
    let groups = st.machine.groups();
    let h = st.history.lock().map_err(|e| e.to_string())?;
    let entries: Vec<EntryView> = h
        .entries
        .iter()
        .map(|e| {
            let can_undo = !e.undone
                && match &e.undo {
                    Some(Undo::Quarantine { id }) => items.iter().any(|i| &i.id == id),
                    Some(Undo::Group { id }) => groups.iter().any(|g| &g.group_id == id && g.can_undo),
                    None => false,
                };
            EntryView { entry: e.clone(), can_undo }
        })
        .collect();
    // Quarantine items the journal made (originals of a repair, clean copies taken back by an
    // undo) belong to their history row, not to the "other" list.
    let mut known: Vec<String> = h
        .entries
        .iter()
        .filter_map(|e| match &e.undo {
            Some(Undo::Quarantine { id }) => Some(id.clone()),
            _ => None,
        })
        .collect();
    let created: Vec<(PathBuf, String)> = groups
        .iter()
        .flat_map(|g| &g.entries)
        .filter_map(|e| {
            if let Some(q) = &e.quarantine_id {
                known.push(q.clone());
            }
            match &e.change {
                genra_av_machine::journal::Change::CreateFile { path, sha256 } => Some((path.clone(), sha256.clone())),
                _ => None,
            }
        })
        .collect();
    let other_quarantine = items
        .into_iter()
        .filter(|i| !known.contains(&i.id) && !created.iter().any(|(p, sha)| *p == i.original_path && sha.eq_ignore_ascii_case(&i.sha256)))
        .collect();
    Ok(HistoryView { entries, other_quarantine })
}

/// What a scan walks: the usual places, every drive, or one folder the user picked.
enum Scope {
    Quick,
    Full,
    Folders(Vec<PathBuf>),
}

/// Starts a scan on a background thread; progress and the result arrive as events.
/// `scope`: `quick` (default) or `full`.
#[tauri::command]
fn quick_scan(app: AppHandle, scope: Option<String>) -> Result<(), String> {
    let scope = match scope.as_deref() {
        None | Some("quick") => Scope::Quick,
        Some("full") => Scope::Full,
        Some(_) => return Err("unknown scope".into()),
    };
    start_scan(app, scope)
}

/// "Thêm thư mục" in "Quét tuỳ chọn": the system picker, several folders at once. Each one is
/// allowed for [`scan_folders`]; an empty list when the picker was closed.
#[tauri::command]
async fn pick_folders(app: AppHandle) -> Result<Vec<String>, String> {
    let a = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || a.dialog().file().blocking_pick_folders())
        .await
        .map_err(|e| e.to_string())?;
    let st = app.state::<AppState>();
    Ok(picked
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| f.into_path().ok())
        .map(|p| {
            st.allow(&p);
            p.to_string_lossy().into_owned()
        })
        .collect())
}

/// Scans the folders the user picked in "Quét tuỳ chọn". The window may only name folders the
/// picker returned.
#[tauri::command]
fn scan_folders(app: AppHandle, folders: Vec<String>) -> Result<(), String> {
    if folders.is_empty() {
        return Err("no_folders".into());
    }
    let st = app.state::<AppState>();
    let dirs = folders.iter().map(|f| st.allowed(f)).collect::<Result<Vec<_>, _>>()?;
    start_scan(app.clone(), Scope::Folders(dirs))
}

/// "Dừng": the running scan ends before its next folder and reports what it found so far.
#[tauri::command]
fn stop_scan(st: St) {
    if st.quick_running.load(Ordering::SeqCst) {
        st.quick_stop.store(true, Ordering::SeqCst);
    }
}

fn start_scan(app: AppHandle, scope: Scope) -> Result<(), String> {
    let st = app.state::<AppState>();
    if st.quick_running.swap(true, Ordering::SeqCst) {
        return Err("busy".into());
    }
    st.quick_stop.store(false, Ordering::SeqCst);
    let a = app.clone();
    std::thread::spawn(move || {
        let st = a.state::<AppState>();
        let (label, mut roots, skip, depth, folder) = match scope {
            Scope::Quick => ("quick", genra_av_core::targets::quick_targets(), Vec::new(), None, None),
            Scope::Full => (
                "full",
                genra_av_core::targets::full_scan_roots(),
                genra_av_core::targets::full_scan_skip(),
                Some(genra_av_core::scanner::DEEP),
                None,
            ),
            Scope::Folders(dirs) => {
                let dirs = genra_av_core::targets::outermost(dirs);
                ("folder", dirs.clone(), Vec::new(), Some(genra_av_core::scanner::DEEP), Some(dirs))
            }
        };
        // Worms on USB sticks hide their copies in hidden folders: walk those on removable drives.
        let usb = genra_av_core::targets::removable_volumes();
        if folder.is_none() {
            roots.extend(usb.iter().cloned());
            roots = genra_av_core::targets::outermost(roots);
            // Office's own XLSTART sits under Program Files, which a whole-drive scan skips:
            // walk it on its own, as the quick scan does.
            roots.extend(
                genra_av_core::targets::excel_startup_dirs()
                    .into_iter()
                    .filter(|d| skip.iter().any(|s| d.starts_with(s))),
            );
        }
        let rules = st.rules();
        let mut walk = genra_av_core::scanner::Walk::quick();
        walk.skip = &skip;
        walk.stop = Some(&st.quick_stop);
        walk.hidden_ok = &usb;
        if let Some(d) = depth {
            walk.max_depth = d;
        }
        let job = quick::Job { scope: label, roots: &roots, walk };
        let result = quick::run_job(&st.data, &rules, &job, |p| {
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
            // "" for the quick scan (older entries have it too), else `full` / `folder`.
            name: if label == "quick" { String::new() } else { label.to_string() },
            path: folder.as_ref().and_then(|d| d.first()).map(|d| d.to_string_lossy().into_owned()),
            verdict: result.hits.iter().filter_map(|h| h.report.verdict).max(),
            family: None,
            files: Some(result.files_seen),
            hits: Some(result.hits.len() as u64),
            undo: None,
            undone: false,
            stopped: result.stopped,
            folders: folder.map(|d| d.len() as u32).unwrap_or(0),
            items: result.hits.iter().take(history::MAX_ITEMS).map(hit_item).collect(),
        });
        st.quick_running.store(false, Ordering::SeqCst);
        let _ = a.emit("quick-done", &result);
    });
    Ok(())
}

fn hit_item(h: &ScanResult) -> HitItem {
    let top = h.report.findings.iter().max_by_key(|f| f.severity);
    HitItem {
        path: h.path.clone(),
        name: h.name.clone(),
        verdict: h.report.verdict,
        family: top.map(|f| f.family.clone()),
        hash_only: h.hash_only,
    }
}

/// "Kiểm tra lại" on a file an earlier quick scan found. The window may only name a path that
/// scan recorded; that path is then allowed for `scan_file` like a file the user picked.
#[tauri::command]
fn recheck_hit(st: St, entry_id: String, path: String) -> Result<(), String> {
    let listed = st
        .history
        .lock()
        .map_err(|e| e.to_string())?
        .entries
        .iter()
        .any(|e| e.id == entry_id && e.kind == Kind::QuickScan && e.items.iter().any(|i| i.path == path));
    if !listed {
        return Err("not_allowed".into());
    }
    st.allow(Path::new(&path));
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

/// "Máy của bạn": health and startup items, read on a background thread once per session
/// (`refresh` reads again). Read-only.
#[tauri::command]
async fn machine_overview(app: AppHandle, refresh: bool) -> Result<Arc<machine::Overview>, String> {
    let st = app.state::<AppState>();
    if !refresh {
        if let Some(o) = st.overview.lock().ok().and_then(|o| o.clone()) {
            return Ok(o);
        }
    }
    let rules = st.rules();
    let a = app.clone();
    let o = tauri::async_runtime::spawn_blocking(move || Arc::new(machine::overview(a.state::<AppState>().machine.as_ref(), &rules)))
        .await
        .map_err(|e| e.to_string())?;
    if let Ok(mut c) = st.overview.lock() {
        *c = Some(o.clone());
    }
    Ok(o)
}

/// "Sửa giúp tôi" on a health item: one journal group, undoable from the history.
#[tauri::command]
async fn fix_health(app: AppHandle, fix: machine::FixId) -> Result<genra_av_machine::repair::RunReport, String> {
    let a = app.clone();
    let report = tauri::async_runtime::spawn_blocking(move || a.state::<AppState>().machine.fix_health(fix)).await.map_err(|e| e.to_string())??;
    let st = app.state::<AppState>();
    if report.outcome == genra_av_machine::repair::Outcome::Done && report.steps.iter().any(|s| s.state == genra_av_machine::repair::StepState::Done) {
        st.record(Entry {
            id: util::new_id(),
            at: util::now(),
            kind: Kind::Fix,
            name: String::new(),
            path: None,
            verdict: None,
            family: serde_json::to_value(fix).ok().and_then(|v| v.as_str().map(String::from)),
            files: None,
            hits: None,
            undo: Some(Undo::Group { id: report.group_id.clone() }),
            undone: false,
            stopped: false,
            folders: 0,
            items: Vec::new(),
        });
    }
    st.invalidate_overview();
    Ok(report)
}

/// "Tắt" on a startup item this user owns: a one-step plan, undoable.
#[tauri::command]
async fn disable_startup(app: AppHandle, id: String) -> Result<genra_av_machine::repair::RunReport, String> {
    let st = app.state::<AppState>();
    let rules = st.rules();
    let a = app.clone();
    let (report, name) = tauri::async_runtime::spawn_blocking(move || -> Result<_, String> {
        let st = a.state::<AppState>();
        let item = st.machine.startup(&rules).into_iter().find(|i| i.id == id).ok_or("startup item not found")?;
        if !machine::can_disable(&item) {
            return Err("this item is not one Genra switches off".into());
        }
        Ok((st.machine.disable_startup(&item)?, item.name))
    })
    .await
    .map_err(|e| e.to_string())??;
    if report.outcome == genra_av_machine::repair::Outcome::Done {
        st.record(Entry {
            id: util::new_id(),
            at: util::now(),
            kind: Kind::StartupOff,
            name,
            path: None,
            verdict: None,
            family: None,
            files: None,
            hits: None,
            undo: Some(Undo::Group { id: report.group_id.clone() }),
            undone: false,
            stopped: false,
            folders: 0,
            items: Vec::new(),
        });
    }
    st.invalidate_overview();
    Ok(report)
}

/// The install id shown in Cài đặt: the same random id sent with reports, so a user can ask for
/// what Genra received from this install to be deleted.
#[tauri::command]
fn get_install_id(st: St) -> Result<String, String> {
    install_id(&st.data)
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

/// What the update check found: a newer signed release, with its notes.
#[derive(serde::Serialize)]
struct UpdateInfo {
    version: String,
    notes: Option<String>,
}

/// Asks the release feed (latest.json on GitHub Releases) for a newer version. The updater only
/// accepts packages signed with the key whose public half is in tauri.conf.json.
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<Option<UpdateInfo>, String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app.updater().map_err(|e| e.to_string())?;
    let found = updater.check().await.map_err(|e| e.to_string())?;
    Ok(found.map(|u| UpdateInfo { version: u.version.clone(), notes: u.body.clone() }))
}

/// Downloads, verifies and installs the update, then restarts into the new version.
#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_updater::UpdaterExt;
    let update = app
        .updater()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no_update".to_string())?;
    update.download_and_install(|_, _| {}, || {}).await.map_err(|e| e.to_string())?;
    app.restart()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let data = genra_av_core::paths::data_dir().or_else(|_| app.path().app_data_dir())?;
            std::fs::create_dir_all(&data)?;
            if let Ok(q) = repair::quarantine(&data) {
                let _ = q.purge_expired();
            }
            if let Ok(j) = genra_av_machine::Journal::open(&data) {
                let _ = j.purge_expired();
            }
            let state = AppState {
                rules: RwLock::new(Arc::new(packs::load(&data))),
                status: Mutex::new(packs::read_status(&data)),
                allow: Mutex::new(Allow::default()),
                history: Mutex::new(History::load(&data)),
                settings: Mutex::new(Settings::load(&data)),
                quick_running: AtomicBool::new(false),
                quick_stop: AtomicBool::new(false),
                machine: Box::new(machine::Real::new(&data)),
                pending: Mutex::new(HashMap::new()),
                overview: Mutex::new(None),
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
            check_update,
            install_update,
            rules_info,
            launch_path,
            pick_file,
            scan_file,
            repair_file,
            continue_repair,
            excel_status,
            close_excel,
            quarantine_file,
            undo,
            history,
            quick_scan,
            pick_folders,
            scan_folders,
            stop_scan,
            recheck_hit,
            reveal,
            open_link,
            machine_overview,
            fix_health,
            disable_startup,
            get_install_id,
            get_settings,
            set_send_hashes,
            report_false_positive
        ])
        .run(tauri::generate_context!())
        .expect("error while running Genra AV");
}
