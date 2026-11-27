//! "Dọn sạch giúp tôi": the fixed list of repair actions, the plan for a detected file, and the
//! runner. Rule packs may only *choose* among [`Action`]s (through `machine_persistence`);
//! there are no free-form actions.
//!
//! The runner checks preconditions first (Excel must not hold what a step touches), runs the
//! steps in order through the [`Journal`], stops at the first failure and undoes the whole group,
//! and reports success only after verifying the result.

use crate::journal::Journal;
use crate::office::{self, ExcelStatus};
use crate::{reg, sha256_hex, startup, traces};
use anyhow::{bail, Context, Result};
use genra_av_core::extract::{self, Kind};
use genra_av_core::reputation::Reputation;
use genra_av_core::rules::{Pack, Severity};
use genra_av_core::{clean, scanner, targets, Report};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfficeApp {
    Excel,
    Word,
    PowerPoint,
}

impl OfficeApp {
    pub fn key_name(self) -> &'static str {
        match self {
            OfficeApp::Excel => "Excel",
            OfficeApp::Word => "Word",
            OfficeApp::PowerPoint => "PowerPoint",
        }
    }
}

/// Office's "Macro Settings". Only the one Office ships with by default is offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacroLevel {
    /// "Disable VBA macros with notification" (VBAWarnings = 2).
    DisableWithNotification,
}

impl MacroLevel {
    pub fn vba_warnings(self) -> u32 {
        match self {
            MacroLevel::DisableWithNotification => 2,
        }
    }
}

/// The whole list of things a repair can do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Write a macro-free copy in place of the file (a new extension if the type changes,
    /// e.g. .xlsm → .xlsx), keep the original in quarantine, verify the copy.
    ReplaceWithClean { path: PathBuf },
    /// Move a file into quarantine if it still has the hash the scan saw.
    QuarantineFile { path: PathBuf, expected_sha256: String },
    /// Move a workbook out of Excel's startup folder into quarantine.
    RemoveXlstartItem { path: PathBuf },
    /// Windows: set Office's macro setting for the current user, only where it is less strict
    /// ("enable all macros") and only for Office versions present. Elsewhere: not applicable.
    SetOfficeMacroPolicy { app: OfficeApp, level: MacroLevel },
    /// Switch off a startup item from [`startup::list`] (user scope only).
    DisableStartupItem { id: String },
    /// Windows: clear Hidden and System on an item a USB worm hid (its other attributes stay).
    Unhide { path: PathBuf },
    /// Stop the threat while it runs (`path` is the threat it runs), if process `pid` is still the
    /// one seen when the plan was made. Not undoable, and nothing to undo: nothing on disk changes.
    StopProcess { pid: u32, started: String, path: PathBuf, program: String },
    /// Switch off a scheduled task that runs a threat (a task this user made).
    DisableScheduledTask { name: String },
    /// Lift a lock malware put on a Windows tool (Task Manager, Registry Editor, Folder Options):
    /// only the values in [`traces::LOCKS`], moved aside so undo puts them back.
    LiftLock { key: String, name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Need {
    /// The app must be closed first: it has a file open that a step replaces, or a step
    /// changes its startup folder while it runs.
    CloseApp { app: String, open_documents: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub action: Action,
    pub title_vi: String,
    pub title_en: String,
    pub needs: Option<Need>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub group_id: String,
    pub steps: Vec<Step>,
    /// One line for the threat screen: "Gỡ sâu khỏi Excel · làm sạch 3 tệp · không đụng gì khác".
    pub summary_vi: String,
    pub summary_en: String,
}

impl Plan {
    /// The first thing the user must do before the plan can run, if any.
    pub fn need(&self) -> Option<Need> {
        merge_needs(self.steps.iter().filter_map(|s| s.needs.clone()))
    }
}

fn merge_needs(needs: impl Iterator<Item = Need>) -> Option<Need> {
    let mut docs: Vec<String> = Vec::new();
    let mut any = false;
    for Need::CloseApp { open_documents, .. } in needs {
        any = true;
        for d in open_documents {
            if !docs.contains(&d) {
                docs.push(d);
            }
        }
    }
    any.then(|| Need::CloseApp { app: "Excel".into(), open_documents: docs })
}

/// What the plan builder looks at. [`Scope::this_machine`] fills it from the real machine;
/// tests pass temporary folders.
pub struct Scope<'a> {
    pub pack: Option<&'a Pack>,
    pub reputation: Option<&'a Reputation>,
    /// Excel startup folders (XLSTART and the macOS equivalent) that exist.
    pub xlstart_dirs: Vec<PathBuf>,
    /// Where other infected workbooks are looked for (the quick-scan targets).
    pub scan_roots: Vec<PathBuf>,
    pub excel: ExcelStatus,
    /// Removable drives mounted now: a threat on one of them also gets the USB worm clean-up.
    pub removable: Vec<PathBuf>,
    /// What starts with the machine; `None` reads it when a plan needs it.
    pub persistence: Option<Vec<startup::Persist>>,
    /// Processes running now; `None` reads them when a plan needs them.
    pub processes: Option<Vec<traces::Running>>,
    /// Locks switched on now (key, value name); `None` reads them when a plan needs them.
    pub locks: Option<Vec<(String, String)>>,
}

impl<'a> Scope<'a> {
    pub fn this_machine(pack: Option<&'a Pack>, reputation: Option<&'a Reputation>) -> Scope<'a> {
        Scope {
            pack,
            reputation,
            xlstart_dirs: xlstart_dirs(),
            scan_roots: targets::quick_targets(),
            excel: office::excel_status(),
            removable: targets::removable_volumes(),
            persistence: None,
            processes: None,
            locks: None,
        }
    }
}

/// Excel's startup folders that exist: XLSTART on Windows, and on macOS the folder Excel 2016+
/// loads at start (`~/Library/Group Containers/UBF8T346G9.Office/User Content.localized/
/// Startup.localized/Excel`, and the older sandbox location).
pub fn xlstart_dirs() -> Vec<PathBuf> {
    let mut out = targets::excel_startup_dirs();
    if cfg!(target_os = "macos") {
        if let Some(h) = crate::home() {
            out.push(h.join("Library/Group Containers/UBF8T346G9.Office/User Content.localized/Startup.localized/Excel"));
            out.push(h.join("Library/Containers/com.microsoft.Excel/Data/Library/Application Support/Microsoft/Office/Startup/Excel"));
        }
    }
    out.retain(|p| p.is_dir());
    out.dedup();
    out
}

fn name_of(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string())
}

/// Where the clean copy of `path` goes: the same path, or the same stem with the new extension.
pub fn clean_destination(path: &Path, new_extension: Option<&str>) -> PathBuf {
    match new_extension {
        Some(ext) if path.extension().and_then(|e| e.to_str()).is_none_or(|e| !e.eq_ignore_ascii_case(ext)) => path.with_extension(ext),
        _ => path.to_path_buf(),
    }
}

/// Families that mean the same infection elsewhere. The built-in "macro" heuristic family is not
/// one: it fires on any macro that runs at open, so on its own it never pulls in another file.
fn threat_families(report: &Report) -> HashSet<String> {
    report.findings.iter().filter(|f| f.severity >= Severity::Suspicious && f.family != "macro").map(|f| f.family.to_ascii_lowercase()).collect()
}

fn module_names(report: &Report) -> Vec<String> {
    let mut v: Vec<String> = report.vba_modules.iter().map(|m| m.name.to_ascii_lowercase()).collect();
    v.sort();
    v
}

/// `other` carries the same infection as `threat`: a shared malware family, or (no family
/// known) exactly the same VBA modules and a suspicious verdict.
pub fn same_infection(threat: &Report, other: &Report) -> bool {
    let fams = threat_families(threat);
    if other.findings.iter().any(|f| f.severity >= Severity::Suspicious && fams.contains(&f.family.to_ascii_lowercase())) {
        return true;
    }
    let names = module_names(threat);
    !names.is_empty() && names == module_names(other) && other.verdict.is_some_and(|v| v >= Severity::Suspicious)
}

/// The threat lives on in Excel's startup folder: Kangatang, or a rule marked
/// `machine_persistence: xlstart`.
fn persists_in_xlstart(report: &Report, pack: Option<&Pack>) -> bool {
    report.findings.iter().any(|f| {
        f.family.eq_ignore_ascii_case("kangatang")
            || pack.and_then(|p| p.rules.iter().find(|r| r.id == f.rule)).and_then(|r| r.machine_persistence.as_deref()).is_some_and(|m| m.eq_ignore_ascii_case("xlstart"))
    })
}

fn replace_step(path: &Path, excel: &ExcelStatus) -> Step {
    let name = name_of(path);
    let needs = excel.has_open(&name).then(|| Need::CloseApp { app: "Excel".into(), open_documents: vec![name.clone()] });
    Step {
        action: Action::ReplaceWithClean { path: path.to_path_buf() },
        title_vi: format!("Làm sạch tệp “{name}”: bỏ macro, giữ nguyên dữ liệu"),
        title_en: format!("Clean “{name}”: remove the macros, keep the data"),
        needs,
    }
}

/// Office types the cleaner can rewrite without macros.
pub fn is_office_document(path: &Path) -> bool {
    const OFFICE: &[&str] = &["doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltm", "xla", "xlam", "ppt", "pptx", "pptm", "pps", "ppsm"];
    path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).is_some_and(|e| OFFICE.contains(&e.as_str()))
}

fn quarantine_step(path: &Path, sha256: &str) -> Step {
    let name = name_of(path);
    Step {
        action: Action::QuarantineFile { path: path.to_path_buf(), expected_sha256: sha256.to_string() },
        title_vi: format!("Cất “{name}” vào khu cách ly (giữ 30 ngày, lấy lại được)"),
        title_en: format!("Move “{name}” to quarantine (kept 30 days, can be restored)"),
        needs: None,
    }
}

/// The USB worm clean-up when the threat sits on a removable drive: quarantine the worm's
/// shortcuts and files, show the user's hidden items again (usb.rs decides what is safe to touch).
fn usb_steps(path: &Path, scope: &Scope, this: &Path) -> Vec<Step> {
    let Some(root) = scope.removable.iter().find(|r| path.starts_with(r)) else { return Vec::new() };
    let layout = crate::usb::layout(root, scope.pack, scope.reputation);
    let mut steps = Vec::new();
    for (p, sha) in layout.shortcuts.iter().chain(layout.payload.iter()) {
        if crate::journal::resolved(p) != this {
            steps.push(quarantine_step(p, sha));
        }
    }
    for p in &layout.hidden {
        let name = name_of(p);
        steps.push(Step {
            action: Action::Unhide { path: p.clone() },
            title_vi: format!("Hiện lại “{name}” trên USB"),
            title_en: format!("Show “{name}” on the USB stick again"),
            needs: None,
        });
    }
    steps
}

/// What the threat left on the machine (ADR 0004, 4b), for a threat that goes to quarantine:
/// steps that must come before quarantining it (stop it running, so Windows lets the file move),
/// steps after (switch off what starts it, lift the locks), and how many startup entries need
/// admin rights Genra does not ask for.
struct MachineSteps {
    before: Vec<Step>,
    after: Vec<Step>,
    needs_admin: usize,
}

fn machine_steps(threats: &[PathBuf], report: &Report, scope: &Scope) -> MachineSteps {
    let mut out = MachineSteps { before: Vec::new(), after: Vec::new(), needs_admin: 0 };
    let processes = scope.processes.clone().unwrap_or_else(traces::running);
    for (p, path) in traces::processes_of(&processes, threats) {
        let program = p.exe.as_deref().map(traces::base_name).unwrap_or_else(|| name_of(&path));
        out.before.push(Step {
            action: Action::StopProcess { pid: p.pid, started: p.started.clone(), path: path.clone(), program: program.clone() },
            title_vi: format!("Dừng “{}” đang chạy", name_of(&path)),
            title_en: format!("Stop “{}”, which is running", name_of(&path)),
            needs: None,
        });
    }
    let persistence = scope.persistence.clone().unwrap_or_else(startup::persistence);
    for e in startup::pointing_at(&persistence, threats) {
        let action = match (&e.kind, e.scope) {
            (startup::PersistKind::Task { name }, _) => Action::DisableScheduledTask { name: name.clone() },
            (startup::PersistKind::Entry, startup::ItemScope::User) => Action::DisableStartupItem { id: e.id.clone() },
            (startup::PersistKind::Entry, startup::ItemScope::System) => {
                out.needs_admin += 1;
                continue;
            }
        };
        out.after.push(Step {
            title_vi: format!("Tắt “{}” tự chạy cùng máy", e.name),
            title_en: format!("Stop “{}” starting with the computer", e.name),
            action,
            needs: None,
        });
    }
    let malware = report.should_quarantine() || report.verdict == Some(Severity::Malware);
    if malware {
        for (key, name) in scope.locks.clone().unwrap_or_else(traces::locks_on) {
            let Some((vi, en)) = traces::lock_label(&key, &name) else { continue };
            out.after.push(Step { action: Action::LiftLock { key, name }, title_vi: format!("Mở lại {vi} bị khoá"), title_en: format!("Unlock {en}"), needs: None });
        }
    }
    out
}

fn xlstart_step(path: &Path, excel: &ExcelStatus) -> Step {
    let name = name_of(path);
    Step {
        action: Action::RemoveXlstartItem { path: path.to_path_buf() },
        title_vi: format!("Gỡ sâu khỏi Excel: cất tệp “{name}” Excel tự mở mỗi lần chạy"),
        title_en: format!("Remove the worm from Excel: move away “{name}”, which Excel opens every time it starts"),
        needs: excel.running.then(|| Need::CloseApp { app: "Excel".into(), open_documents: excel.open_documents.clone() }),
    }
}

fn scan_path(path: &Path, scope: &Scope) -> Option<Report> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() || md.len() > scanner::MAX_FILE {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(genra_av_core::scan_with(&bytes, scope.pack, scope.reputation))
}

/// The "Dọn sạch giúp tôi" plan for a detected file, looking at this machine.
pub fn plan_for_threat(path: &Path, report: &Report) -> Plan {
    plan_for_threat_in(path, report, &Scope::this_machine(None, None))
}

/// The plan for a detected file: replace it with a clean copy; when the threat persists in
/// Excel's startup folder, also take the infected items out of it and clean the other
/// workbooks in the quick-scan places that carry the same infection.
///
/// A detected file that itself sits in an Excel startup folder is the worm's copy, not a user
/// document: it is moved out of the folder (quarantine) instead of being cleaned in place.
pub fn plan_for_threat_in(path: &Path, report: &Report, scope: &Scope) -> Plan {
    let this = crate::journal::resolved(path);
    let in_xlstart = |p: &Path| targets::in_startup_folder(p) || p.parent().is_some_and(|d| scope.xlstart_dirs.iter().any(|x| x == d || crate::journal::resolved(x) == crate::journal::resolved(d)));
    let threat_in_xlstart = in_xlstart(path);
    // Office documents are cleaned (data kept); anything else (a shortcut, a script, a program)
    // has nothing to keep and is moved to quarantine.
    let first = if threat_in_xlstart {
        xlstart_step(path, &scope.excel)
    } else if is_office_document(path) {
        replace_step(path, &scope.excel)
    } else {
        quarantine_step(path, &report.sha256)
    };
    let quarantined = matches!(first.action, Action::QuarantineFile { .. });
    let mut steps = vec![first];
    let usb = usb_steps(path, scope, &this);
    let usb_counts = (usb.iter().filter(|s| matches!(s.action, Action::QuarantineFile { .. })).count(), usb.iter().filter(|s| matches!(s.action, Action::Unhide { .. })).count());
    let mut machine = MachineSteps { before: Vec::new(), after: Vec::new(), needs_admin: 0 };
    if quarantined {
        let mut threats = vec![path.to_path_buf()];
        threats.extend(usb.iter().filter_map(|s| if let Action::QuarantineFile { path, .. } = &s.action { Some(path.clone()) } else { None }));
        machine = machine_steps(&threats, report, scope);
    }
    steps.splice(0..0, std::mem::take(&mut machine.before));
    let stopped = steps.iter().filter(|s| matches!(s.action, Action::StopProcess { .. })).count();
    steps.extend(usb);
    let startup_off = machine.after.iter().filter(|s| matches!(s.action, Action::DisableStartupItem { .. } | Action::DisableScheduledTask { .. })).count();
    let unlocked = machine.after.len() - startup_off;
    steps.extend(machine.after);
    let mut xlstart = usize::from(threat_in_xlstart);
    if persists_in_xlstart(report, scope.pack) {
        for dir in &scope.xlstart_dirs {
            let Ok(rd) = std::fs::read_dir(dir) else { continue };
            let mut files: Vec<PathBuf> = rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_file())).map(|e| e.path()).collect();
            files.sort();
            for f in files {
                if crate::journal::resolved(&f) == this {
                    continue;
                }
                if let Some(r) = scan_path(&f, scope) {
                    if same_infection(report, &r) || r.should_quarantine() {
                        steps.push(xlstart_step(&f, &scope.excel));
                        xlstart += 1;
                    }
                }
            }
        }
        let mut ctx = scanner::Context::new(scope.pack, scope.reputation, scanner::Cache::default());
        let summary = scanner::walk(&mut ctx, &scope.scan_roots, |_| {});
        let mut seen: HashSet<PathBuf> = HashSet::from([this]);
        let mut others: Vec<PathBuf> = summary
            .hits
            .iter()
            .filter(|h| matches!(h.report.kind, Kind::Ole | Kind::Zip) && targets::interesting(&h.path))
            .filter(|h| !scope.xlstart_dirs.iter().any(|d| h.path.starts_with(d)) && !targets::in_startup_folder(&h.path))
            .filter(|h| same_infection(report, &h.report))
            .map(|h| h.path.clone())
            .collect();
        others.sort();
        for o in others {
            if seen.insert(crate::journal::resolved(&o)) {
                steps.push(replace_step(&o, &scope.excel));
            }
        }
    }
    let files = steps.iter().filter(|s| matches!(s.action, Action::ReplaceWithClean { .. })).count();
    let (mut extra_vi, mut extra_en) = (String::new(), String::new());
    for (n, vi, en) in [
        (stopped, "dừng {n} chương trình đang chạy", "stop {n} running program(s)"),
        (startup_off, "tắt {n} mục tự chạy cùng máy", "switch off {n} startup item(s)"),
        (unlocked, "mở lại {n} công cụ bị khoá", "unlock {n} Windows tool(s)"),
        (machine.needs_admin, "{n} mục tự chạy cần quyền quản trị, Genra không đổi", "{n} startup item(s) need admin rights; Genra leaves them"),
    ] {
        if n > 0 {
            extra_vi.push_str(&format!(" · {}", vi.replace("{n}", &n.to_string())));
            extra_en.push_str(&format!(" · {}", en.replace("{n}", &n.to_string())));
        }
    }
    let (summary_vi, summary_en) = if usb_counts.1 > 0 {
        (
            format!("Dọn USB: cất {} tệp của sâu · hiện lại {} thư mục, tệp bị giấu{extra_vi} · không xoá gì", usb_counts.0 + 1, usb_counts.1),
            format!("Clean the USB stick: move away {} worm file(s) · show {} hidden folder(s) and file(s) again{extra_en} · nothing deleted", usb_counts.0 + 1, usb_counts.1),
        )
    } else if files == 0 && xlstart == 0 {
        (format!("Cất tệp vào khu cách ly{extra_vi} · không đụng gì khác"), format!("Move the file to quarantine{extra_en} · nothing else is touched"))
    } else if xlstart > 0 && files == 0 {
        ("Gỡ sâu khỏi Excel · không đụng gì khác".to_string(), "Remove the worm from Excel · nothing else is touched".to_string())
    } else if xlstart > 0 {
        (format!("Gỡ sâu khỏi Excel · làm sạch {files} tệp · không đụng gì khác"), format!("Remove the worm from Excel · clean {files} file(s) · nothing else is touched"))
    } else {
        (format!("Làm sạch {files} tệp · không đụng gì khác"), format!("Clean {files} file(s) · nothing else is touched"))
    };
    Plan { group_id: Journal::new_group_id().unwrap_or_else(|_| format!("{:016x}", crate::now())), steps, summary_vi, summary_en }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Started,
    Done,
    /// Nothing to do here (already as wanted, or not applicable on this system).
    Skipped,
    /// Not done because Windows did not allow it (admin rights, a process that resists); the
    /// repair carries on and the step says what happens instead.
    NotAllowed,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepProgress {
    pub index: usize,
    pub total: usize,
    pub title_vi: String,
    pub title_en: String,
    pub state: StepState,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub index: usize,
    pub title_vi: String,
    pub title_en: String,
    pub state: StepState,
    pub detail_vi: String,
    pub detail_en: String,
    /// Technical error text, for "Xem chi tiết".
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanedFile {
    pub original_path: PathBuf,
    /// Where the clean copy is (the same path unless the type changed, .xlsm → .xlsx).
    pub clean_path: PathBuf,
    pub removed: Vec<String>,
    pub kept: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outcome {
    /// Every step done and the result verified.
    Done,
    /// Nothing changed: the user must do this first (close Excel).
    NeedsAction { need: Need },
    /// A step failed (or the check after failed); everything done before was undone.
    RolledBack { failed_step: usize, error: String },
    /// A step failed and undoing the group failed too; originals are still in quarantine.
    RollbackFailed { failed_step: usize, error: String, rollback_error: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub group_id: String,
    pub outcome: Outcome,
    pub steps: Vec<StepResult>,
    /// The result was checked after the last step (clean copies re-read and re-scanned).
    pub verified: bool,
    pub cleaned: Vec<CleanedFile>,
    pub title_vi: String,
    pub title_en: String,
    pub detail_vi: String,
    pub detail_en: String,
}

/// Runs a plan on this machine (Excel's state is read now, not taken from the plan).
pub fn run(plan: &Plan, journal: &mut Journal, progress: impl FnMut(StepProgress)) -> RunReport {
    run_in(plan, journal, office::excel_status, progress)
}

/// What a step did, kept for the check at the end.
enum Did {
    Cleaned(CleanedFile),
    Removed(PathBuf),
    Other,
}

/// [`run`] with Excel's state supplied by the caller.
pub fn run_in(plan: &Plan, journal: &mut Journal, excel: impl Fn() -> ExcelStatus, mut progress: impl FnMut(StepProgress)) -> RunReport {
    let total = plan.steps.len();
    let mut report = RunReport {
        group_id: plan.group_id.clone(),
        outcome: Outcome::Done,
        steps: Vec::new(),
        verified: false,
        cleaned: Vec::new(),
        title_vi: String::new(),
        title_en: String::new(),
        detail_vi: String::new(),
        detail_en: String::new(),
    };

    // Precondition, with Excel as it is now: nothing is changed while Excel holds a file.
    let now = if plan.steps.iter().any(|s| matches!(s.action, Action::ReplaceWithClean { .. } | Action::RemoveXlstartItem { .. })) { excel() } else { ExcelStatus::default() };
    let needs = merge_needs(plan.steps.iter().filter_map(|s| match &s.action {
        Action::ReplaceWithClean { path } => now.has_open(&name_of(path)).then(|| Need::CloseApp { app: "Excel".into(), open_documents: vec![name_of(path)] }),
        Action::RemoveXlstartItem { .. } if now.running => Some(Need::CloseApp { app: "Excel".into(), open_documents: now.open_documents.clone() }),
        _ => None,
    }));
    if let Some(need) = needs {
        let Need::CloseApp { open_documents, .. } = &need;
        let docs = if open_documents.is_empty() { String::new() } else { format!(" ({})", open_documents.join(", ")) };
        report.title_vi = "Cần đóng Excel trước khi dọn".into();
        report.title_en = "Excel needs to close first".into();
        report.detail_vi = format!("Excel đang mở{docs}. Genra chưa thay đổi gì. Bấm “Đóng Excel giúp tôi”: Excel sẽ hỏi bạn có lưu bài không, rồi Genra dọn tiếp.");
        report.detail_en = format!("Excel is open{docs}. Genra has not changed anything. Press “Close Excel for me”: Excel will ask whether to save your work, then Genra carries on.");
        report.outcome = Outcome::NeedsAction { need };
        return report;
    }

    let mut did = Vec::new();
    let mut failure: Option<(usize, String)> = None;
    for (i, step) in plan.steps.iter().enumerate() {
        let p = |state| StepProgress { index: i, total, title_vi: step.title_vi.clone(), title_en: step.title_en.clone(), state };
        progress(p(StepState::Started));
        match do_step(&step.action, &plan.group_id, journal) {
            Ok((state, d, vi, en)) => {
                progress(p(state));
                report.steps.push(StepResult { index: i, title_vi: step.title_vi.clone(), title_en: step.title_en.clone(), state, detail_vi: vi, detail_en: en, error: None });
                did.push(d);
            }
            Err(e) => {
                progress(p(StepState::Failed));
                let err = format!("{e:#}");
                report.steps.push(StepResult {
                    index: i,
                    title_vi: step.title_vi.clone(),
                    title_en: step.title_en.clone(),
                    state: StepState::Failed,
                    detail_vi: "Bước này không làm được.".into(),
                    detail_en: "This step could not be done.".into(),
                    error: Some(err.clone()),
                });
                failure = Some((i, err));
                break;
            }
        }
    }

    if failure.is_none() {
        match verify(&did) {
            Ok(()) => report.verified = true,
            Err(e) => failure = Some((total.saturating_sub(1), format!("check after repair: {e:#}"))),
        }
    }

    match failure {
        None => {
            report.cleaned = did.into_iter().filter_map(|d| if let Did::Cleaned(c) = d { Some(c) } else { None }).collect();
            let files = report.cleaned.len();
            let xl = plan.steps.iter().any(|s| matches!(s.action, Action::RemoveXlstartItem { .. }));
            report.title_vi = "Đã dọn xong, máy hoạt động bình thường".into();
            report.title_en = "All clean. Your computer works as before".into();
            report.detail_vi = format!(
                "Genra đã {}làm sạch {files} tệp, rồi kiểm tra lại từng tệp. Tệp vẫn ở chỗ cũ, mở bình thường. Bản gốc được giữ 30 ngày; bấm “Hoàn tác” nếu cần.",
                if xl { "gỡ sâu khỏi Excel, " } else { "" }
            );
            report.detail_en = format!(
                "Genra {}cleaned {files} file(s), then checked each one again. They are where they were and open as usual. The originals are kept for 30 days; press “Undo” if you need them.",
                if xl { "removed the worm from Excel, " } else { "" }
            );
        }
        Some((failed_step, error)) => {
            let title = plan.steps.get(failed_step).map(|s| (s.title_vi.clone(), s.title_en.clone())).unwrap_or_default();
            // A step that failed before writing anything leaves no group to undo.
            let undone = if journal.group(&plan.group_id).is_ok() { journal.undo_group(&plan.group_id).map(|_| ()) } else { Ok(()) };
            match undone {
                Ok(_) => {
                    report.title_vi = "Chưa dọn được, máy vẫn như cũ".into();
                    report.title_en = "Not cleaned yet; nothing was changed".into();
                    report.detail_vi = format!("Genra gặp lỗi ở bước “{}” nên đã đưa mọi thứ về như trước. Tệp và máy của bạn không thay đổi. Bạn có thể thử lại.", title.0);
                    report.detail_en = format!("Genra hit a problem at “{}”, so it put everything back the way it was. Your files and computer are unchanged. You can try again.", title.1);
                    report.outcome = Outcome::RolledBack { failed_step, error };
                }
                Err(rb) => {
                    report.title_vi = "Chưa dọn xong".into();
                    report.title_en = "The repair did not finish".into();
                    report.detail_vi = format!("Genra gặp lỗi ở bước “{}” và chưa đưa được mọi thứ về như cũ. Tệp gốc vẫn an toàn trong khu cách ly. Bấm “Hoàn tác” để thử lại.", title.0);
                    report.detail_en = format!("Genra hit a problem at “{}” and could not put everything back yet. The original files are safe in quarantine. Press “Undo” to try again.", title.1);
                    report.outcome = Outcome::RollbackFailed { failed_step, error, rollback_error: format!("{rb:#}") };
                }
            }
            report.cleaned.clear();
        }
    }
    report
}

/// A clean copy is good when it parses as the same kind of container, has no VBA left and
/// nothing unreadable.
fn check_clean(bytes: &[u8], kind: Kind) -> Result<()> {
    let r = genra_av_core::scan(bytes, None);
    if r.kind != kind {
        bail!("the clean copy is not the same kind of file");
    }
    let f = extract::facts(bytes);
    if !f.vba.is_empty() || f.vba_unreadable {
        bail!("the clean copy still has macros or parts that cannot be read");
    }
    match kind {
        Kind::Ole => {
            cfb::CompoundFile::open(std::io::Cursor::new(bytes)).context("the clean copy does not open as an Office 97-2003 file")?;
        }
        Kind::Zip => {
            zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("the clean copy does not open as an Office file")?;
        }
        Kind::Other => bail!("not an Office file"),
    }
    Ok(())
}

fn read_regular(path: &Path, max: u64) -> Result<Vec<u8>> {
    let md = std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !md.is_file() {
        bail!("{} is not a regular file (links are not followed)", path.display());
    }
    if md.len() > max {
        bail!("{} is over {} MB", path.display(), max / 1024 / 1024);
    }
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

type StepDone = (StepState, Did, String, String);

fn do_step(action: &Action, group: &str, j: &mut Journal) -> Result<StepDone> {
    match action {
        Action::ReplaceWithClean { path } => {
            let bytes = read_regular(path, clean::MAX_INPUT as u64)?;
            let kind = extract::kind(&bytes);
            let cleaned = clean::clean(&bytes)?;
            check_clean(&cleaned.bytes, kind)?;
            let dest = clean_destination(path, cleaned.new_extension);
            if dest != *path && std::fs::symlink_metadata(&dest).is_ok() {
                bail!("{} already exists; not overwriting it", dest.display());
            }
            let name = name_of(path);
            j.quarantine_file(group, path, &sha256_hex(&bytes), "Dọn sạch giúp tôi: bản gốc có macro / original with macros", &format!("Cất bản gốc “{name}” vào khu cách ly"), &format!("Move the original “{name}” to quarantine"))?;
            j.create_file(group, &dest, &cleaned.bytes, &format!("Ghi bản sạch “{}”", name_of(&dest)), &format!("Write the clean copy “{}”", name_of(&dest)))?;
            let back = read_regular(&dest, clean::MAX_INPUT as u64)?;
            if back != cleaned.bytes {
                bail!("the clean copy on disk is not what Genra wrote");
            }
            check_clean(&back, kind)?;
            let (vi, en) = if dest == *path {
                ("Đã thay bằng bản sạch, cùng tên, cùng chỗ.".to_string(), "Replaced with a clean copy, same name, same place.".to_string())
            } else {
                (format!("Đã thay bằng bản sạch “{}” (loại tệp không chứa macro).", name_of(&dest)), format!("Replaced with the clean copy “{}” (a file type that holds no macros).", name_of(&dest)))
            };
            Ok((StepState::Done, Did::Cleaned(CleanedFile { original_path: path.clone(), clean_path: dest, removed: cleaned.removed, kept: cleaned.kept }), vi, en))
        }
        Action::QuarantineFile { path, expected_sha256 } => {
            let name = name_of(path);
            j.quarantine_file(group, path, expected_sha256, "Dọn sạch giúp tôi", &format!("Cất “{name}” vào khu cách ly"), &format!("Move “{name}” to quarantine"))?;
            Ok((StepState::Done, Did::Removed(path.clone()), "Đã cất vào khu cách ly (giữ 30 ngày).".into(), "Moved to quarantine (kept for 30 days).".into()))
        }
        Action::RemoveXlstartItem { path } => {
            let in_xlstart = targets::in_startup_folder(path) || path.parent().is_some_and(|p| xlstart_dirs().iter().any(|d| d == p));
            if !in_xlstart {
                bail!("{} is not in an Excel startup folder", path.display());
            }
            let bytes = read_regular(path, scanner::MAX_FILE)?;
            let f = extract::facts(&bytes);
            if f.vba.is_empty() && !f.vba_unreadable {
                bail!("{} has no macros (any more); leaving it", path.display());
            }
            let name = name_of(path);
            j.quarantine_file(group, path, &sha256_hex(&bytes), "Dọn sạch giúp tôi: sâu trong thư mục khởi động Excel / worm in Excel's startup folder", &format!("Cất “{name}” khỏi thư mục khởi động của Excel"), &format!("Move “{name}” out of Excel's startup folder"))?;
            Ok((StepState::Done, Did::Removed(path.clone()), "Excel không còn tự mở tệp này.".into(), "Excel no longer opens this file at start.".into()))
        }
        Action::SetOfficeMacroPolicy { app, level } => set_macro_policy(*app, *level, group, j),
        Action::DisableStartupItem { id } => {
            let (vi, en) = startup::disable(id, group, j)?;
            Ok((StepState::Done, Did::Other, vi, en))
        }
        Action::Unhide { path } => {
            let mask = crate::attrs::HIDDEN | crate::attrs::SYSTEM;
            let now = crate::attrs::get(path)?;
            if now & mask == 0 {
                return Ok((StepState::Skipped, Did::Other, "Đã hiện sẵn.".into(), "Already visible.".into()));
            }
            let name = name_of(path);
            j.set_attributes(group, path, now & !mask, &format!("Hiện lại “{name}”"), &format!("Show “{name}” again"))?;
            Ok((StepState::Done, Did::Other, "Đã hiện lại, dữ liệu vẫn nguyên.".into(), "Visible again; the data is untouched.".into()))
        }
        // The next three never fail the repair: what they could not do is said in the step, and
        // the threat itself still goes to quarantine.
        Action::StopProcess { pid, started, path, .. } => Ok(match traces::stop(*pid, started, path) {
            Ok(traces::Stopped::Stopped) => (StepState::Done, Did::Other, "Đã dừng.".into(), "Stopped.".into()),
            Ok(traces::Stopped::Gone) => (StepState::Skipped, Did::Other, "Đã tự dừng trước đó.".into(), "It had already stopped.".into()),
            Ok(traces::Stopped::Refused) | Err(_) => (
                StepState::NotAllowed,
                Did::Other,
                "Windows không cho dừng lúc này. Sau khi khởi động lại máy, nó sẽ không chạy nữa.".into(),
                "Windows would not stop it now. After a restart it will not run again.".into(),
            ),
        }),
        Action::DisableScheduledTask { name } => {
            let short = name.rsplit('\\').next().unwrap_or(name);
            match j.disable_task(group, name, &format!("Tắt tác vụ hẹn giờ “{short}”"), &format!("Switch off the scheduled task “{short}”")) {
                Ok(()) => Ok((StepState::Done, Did::Other, "Sẽ không tự chạy nữa.".into(), "It will not run on its own any more.".into())),
                Err(_) => Ok((
                    StepState::NotAllowed,
                    Did::Other,
                    "Tác vụ này cần quyền quản trị để tắt; Genra không đổi.".into(),
                    "This task needs admin rights to switch off; Genra leaves it.".into(),
                )),
            }
        }
        Action::LiftLock { key, name } => {
            let Some((vi, en)) = traces::lock_label(key, name) else { bail!("{key}\\{name} is not a lock Genra lifts") };
            if !matches!(reg::get(key, name), Ok(Some(reg::RegValue::Dword(n))) if n != 0) {
                return Ok((StepState::Skipped, Did::Other, "Đã mở sẵn.".into(), "Already unlocked.".into()));
            }
            match j.move_registry_value(group, key, name, &traces::lock_backup(key), &format!("Mở lại {vi}"), &format!("Unlock {en}")) {
                Ok(()) => Ok((StepState::Done, Did::Other, format!("Bạn mở lại được {vi}."), format!("You can open {en} again."))),
                Err(_) => Ok((StepState::NotAllowed, Did::Other, "Không mở được khoá này; Genra không đổi.".into(), "This lock could not be lifted; Genra leaves it.".into())),
            }
        }
    }
}

fn verify(did: &[Did]) -> Result<()> {
    for d in did {
        match d {
            Did::Cleaned(c) => {
                let bytes = read_regular(&c.clean_path, clean::MAX_INPUT as u64)?;
                check_clean(&bytes, extract::kind(&bytes))?;
            }
            Did::Removed(p) => {
                if std::fs::symlink_metadata(p).is_ok() {
                    // Something put a file back (the worm re-copying itself while Excel ran).
                    bail!("{} is back", p.display());
                }
            }
            Did::Other => {}
        }
    }
    Ok(())
}

/// Office versions installed for this user (`16.0`, `15.0`, ...) that have `app`'s key.
fn office_versions(app: OfficeApp) -> Vec<String> {
    let base = "HKCU\\Software\\Microsoft\\Office";
    let mut v: Vec<String> = reg::subkeys(base)
        .unwrap_or_default()
        .into_iter()
        .filter(|k| is_office_version(k))
        .filter(|k| reg::subkeys(&format!("{base}\\{k}")).unwrap_or_default().iter().any(|s| s.eq_ignore_ascii_case(app.key_name())))
        .collect();
    v.sort();
    v
}

pub(crate) fn is_office_version(k: &str) -> bool {
    let mut parts = k.split('.');
    matches!((parts.next(), parts.next(), parts.next()), (Some(a), Some(b), None) if !a.is_empty() && !b.is_empty() && a.bytes().chain(b.bytes()).all(|c| c.is_ascii_digit()))
}

/// `VBAWarnings` keys of `app` for the Office versions present, with their current value.
pub(crate) fn macro_settings(app: OfficeApp) -> Vec<(String, Option<u32>)> {
    office_versions(app)
        .into_iter()
        .map(|ver| {
            let key = format!("HKCU\\Software\\Microsoft\\Office\\{ver}\\{}\\Security", app.key_name());
            let cur = match reg::get(&key, "VBAWarnings") {
                Ok(Some(reg::RegValue::Dword(n))) => Some(n),
                _ => None,
            };
            (key, cur)
        })
        .collect()
}

fn set_macro_policy(app: OfficeApp, level: MacroLevel, group: &str, j: &mut Journal) -> Result<StepDone> {
    if !cfg!(windows) {
        return Ok((StepState::Skipped, Did::Other, "Không áp dụng trên máy này.".into(), "Not applicable on this computer.".into()));
    }
    let want = level.vba_warnings();
    let mut changed = 0;
    let settings = macro_settings(app);
    for (key, cur) in &settings {
        // Only a less strict setting is raised; a stricter one the user or IT chose stays.
        if cur.is_some_and(|c| c < want) {
            j.set_registry_value(
                group,
                key,
                "VBAWarnings",
                reg::RegValue::Dword(want),
                &format!("Đặt lại cài đặt macro của {}: tắt macro, có thông báo", app.key_name()),
                &format!("Reset {}'s macro setting: disable macros, with a notification", app.key_name()),
            )?;
            changed += 1;
        }
    }
    if changed == 0 {
        let (vi, en) = if settings.is_empty() {
            (format!("Máy không có {} cho tài khoản này.", app.key_name()), format!("{} is not set up for this account.", app.key_name()))
        } else {
            ("Cài đặt đã an toàn, không cần đổi.".to_string(), "The setting is already safe; nothing to change.".to_string())
        };
        return Ok((StepState::Skipped, Did::Other, vi, en));
    }
    Ok((
        StepState::Done,
        Did::Other,
        format!("{} sẽ không tự chạy macro nữa; tệp có macro sẽ hiện thanh báo để bạn chọn.", app.key_name()),
        format!("{} no longer runs macros on its own; a file with macros shows a bar so you can choose.", app.key_name()),
    ))
}

#[cfg(test)]
pub(crate) mod tests;
