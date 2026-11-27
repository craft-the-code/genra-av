//! Seam for machine-level work: repair plans that reach beyond one file (the worm in Excel's
//! startup folder, other infected workbooks), undo by journal group, Excel's state, health checks
//! and programs that start with the computer. [`Real`] implements [`Machine`] with
//! `genra-av-machine`; the commands in `lib.rs` only talk to the trait, so a test or another
//! platform can swap the implementation without touching the window.

use crate::packs::Loaded;
use genra_av_core::Report;
use genra_av_machine::journal::{Change, Group, UndoReport};
use genra_av_machine::repair::{self, Action, Plan, RunReport, Scope, Step, StepProgress};
use genra_av_machine::startup::{ItemScope, StartupItem, Verdict};
use genra_av_machine::{health, office, startup, Journal};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub use genra_av_machine::health::{FixId, HealthItem};
pub use genra_av_machine::office::ExcelStatus;

pub type MachineResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

pub trait Machine: Send + Sync {
    /// The "Dọn sạch giúp tôi" plan for a detected file, judged with the installed rules.
    fn plan_for_threat(&self, path: &Path, report: &Report, rules: &Loaded) -> Plan;
    /// Runs a plan as one journal group. Excel's state is read again first: a plan that needs
    /// Excel closed comes back as `NeedsAction` with nothing changed, and can be run again.
    fn run_plan(&self, plan: &Plan, progress: &mut dyn FnMut(StepProgress)) -> MachineResult<RunReport>;
    /// Undoes one journal group; returns the report and the paths put back.
    fn undo_group(&self, group_id: &str) -> MachineResult<(UndoReport, Vec<PathBuf>)>;
    /// Journal groups, newest first (for "Lịch sử & hoàn tác").
    fn groups(&self) -> Vec<Group>;
    fn excel_status(&self) -> ExcelStatus;
    fn ask_excel_to_close(&self) -> MachineResult<()>;
    fn health(&self) -> Vec<HealthItem>;
    fn fix_health(&self, id: FixId) -> MachineResult<RunReport>;
    fn startup(&self, rules: &Loaded) -> Vec<StartupItem>;
    /// Switches one startup item off through a one-step plan (one journal group, undoable).
    fn disable_startup(&self, item: &StartupItem) -> MachineResult<RunReport>;
}

/// The real machine. Every change goes through the journal in `<data>/journal/` and the
/// quarantine in `<data>/quarantine/`; one change at a time.
pub struct Real {
    data: PathBuf,
    busy: Mutex<()>,
}

impl Real {
    pub fn new(data: &Path) -> Real {
        Real { data: data.to_path_buf(), busy: Mutex::new(()) }
    }

    fn journal(&self) -> MachineResult<Journal> {
        Journal::open(&self.data).map_err(|e| format!("{e:#}"))
    }
}

/// Debug builds only: `GENRA_AV_E2E_EXCEL=<file>` stands in for Excel, so the "close Excel" flow
/// can be checked without starting the real Excel. While the file exists Excel "runs" with the
/// workbooks named in it (one per line); asking it to close removes the file two seconds later.
/// Release builds do not contain this.
#[cfg(debug_assertions)]
fn fake_excel() -> Option<PathBuf> {
    std::env::var_os("GENRA_AV_E2E_EXCEL").map(PathBuf::from)
}
#[cfg(not(debug_assertions))]
fn fake_excel() -> Option<PathBuf> {
    None
}

impl Machine for Real {
    fn plan_for_threat(&self, path: &Path, report: &Report, rules: &Loaded) -> Plan {
        let scope = Scope {
            pack: Some(&rules.pack),
            reputation: Some(&rules.reputation),
            xlstart_dirs: repair::xlstart_dirs(),
            scan_roots: genra_av_core::targets::quick_targets(),
            excel: self.excel_status(),
            removable: genra_av_core::targets::removable_volumes(),
            persistence: None,
            processes: None,
            locks: None,
        };
        repair::plan_for_threat_in(path, report, &scope)
    }

    fn run_plan(&self, plan: &Plan, progress: &mut dyn FnMut(StepProgress)) -> MachineResult<RunReport> {
        let _one = self.busy.lock().map_err(err)?;
        let mut j = self.journal()?;
        Ok(repair::run_in(plan, &mut j, || self.excel_status(), progress))
    }

    fn undo_group(&self, group_id: &str) -> MachineResult<(UndoReport, Vec<PathBuf>)> {
        let _one = self.busy.lock().map_err(err)?;
        let mut j = self.journal()?;
        let back: Vec<PathBuf> = j
            .group(group_id)
            .map_err(|e| format!("{e:#}"))?
            .into_iter()
            .filter_map(|e| match e.change {
                Change::Quarantine { path, .. } => Some(path),
                _ => None,
            })
            .collect();
        let report = j.undo_group(group_id).map_err(|e| format!("{e:#}"))?;
        Ok((report, back))
    }

    fn groups(&self) -> Vec<Group> {
        self.journal().ok().and_then(|j| j.groups().ok()).unwrap_or_default()
    }

    fn excel_status(&self) -> ExcelStatus {
        if let Some(f) = fake_excel() {
            return match std::fs::read_to_string(&f) {
                Ok(s) => ExcelStatus { running: true, open_documents: s.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect() },
                Err(_) => ExcelStatus::default(),
            };
        }
        office::excel_status()
    }

    fn ask_excel_to_close(&self) -> MachineResult<()> {
        if let Some(f) = fake_excel() {
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let _ = std::fs::remove_file(f);
            });
            return Ok(());
        }
        office::ask_excel_to_close().map_err(|e| format!("{e:#}"))
    }

    fn health(&self) -> Vec<HealthItem> {
        health::check()
    }

    fn fix_health(&self, id: FixId) -> MachineResult<RunReport> {
        let _one = self.busy.lock().map_err(err)?;
        let mut j = self.journal()?;
        health::fix(id, &mut j).map_err(|e| format!("{e:#}"))
    }

    fn startup(&self, rules: &Loaded) -> Vec<StartupItem> {
        startup::list_with(Some(&rules.pack), Some(&rules.reputation))
    }

    fn disable_startup(&self, item: &StartupItem) -> MachineResult<RunReport> {
        self.run_plan(&disable_plan(item)?, &mut |_| {})
    }
}

/// The one-step plan behind "Tắt".
fn disable_plan(item: &StartupItem) -> MachineResult<Plan> {
    Ok(Plan {
        group_id: Journal::new_group_id().map_err(|e| format!("{e:#}"))?,
        steps: vec![Step {
            action: Action::DisableStartupItem { id: item.id.clone() },
            title_vi: format!("Tắt “{}” khi khởi động máy", item.name),
            title_en: format!("Stop “{}” starting with the computer", item.name),
            needs: None,
        }],
        summary_vi: format!("Tắt “{}” · không đụng gì khác", item.name),
        summary_en: format!("Switch off “{}” · nothing else is touched", item.name),
    })
}

/// Only this user's items that look wrong get a "Tắt" button; the whole machine's items need
/// admin rights, which Genra never asks for.
pub fn can_disable(item: &StartupItem) -> bool {
    item.scope == ItemScope::User && matches!(item.verdict, Verdict::Warn | Verdict::Bad)
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupView {
    #[serde(flatten)]
    pub item: StartupItem,
    pub can_disable: bool,
}

/// One place the quick scan and the folder guard (guard.rs) look at.
#[derive(Debug, Clone, Serialize)]
pub struct GuardPlace {
    /// `downloads`, `zalo` or `usb`.
    pub kind: &'static str,
    /// The folders (or mounted drives) found on this machine; empty when there is none now.
    pub paths: Vec<String>,
}

pub fn guard_places() -> Vec<GuardPlace> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
    let existing = |subs: &[&str]| -> Vec<String> {
        home.iter().flat_map(|h| subs.iter().map(move |s| h.join(s))).filter(|p| p.is_dir()).map(|p| p.to_string_lossy().into_owned()).collect()
    };
    vec![
        GuardPlace { kind: "downloads", paths: existing(&["Downloads"]) },
        GuardPlace { kind: "zalo", paths: existing(&["Documents/Zalo Received Files", "Zalo Received Files"]) },
        GuardPlace { kind: "usb", paths: genra_av_core::targets::removable_volumes().into_iter().map(|p| p.to_string_lossy().into_owned()).collect() },
    ]
}

/// What "Máy của bạn" renders, read once per session (and again after a change).
#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub health: Vec<HealthItem>,
    pub startup: Vec<StartupView>,
    pub guard: Vec<GuardPlace>,
}

/// Health and startup items are read side by side: on Windows each waits on PowerShell
/// (Defender status, signatures) for several seconds, so running them in turn doubled the wait.
pub fn overview(m: &(dyn Machine + Sync), rules: &Loaded) -> Overview {
    let (health, startup) = std::thread::scope(|s| {
        let h = s.spawn(|| m.health());
        let startup: Vec<StartupView> = m.startup(rules).into_iter().map(|item| StartupView { can_disable: can_disable(&item), item }).collect();
        (h.join().unwrap_or_default(), startup)
    });
    Overview { health, startup, guard: guard_places() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(scope: ItemScope, verdict: Verdict) -> StartupItem {
        StartupItem {
            id: "file:/x".into(),
            name: "x".into(),
            location: "~/Library/LaunchAgents".into(),
            command: "x".into(),
            scope,
            signed: Some(false),
            publisher: None,
            verdict,
            reason_vi: String::new(),
            reason_en: String::new(),
        }
    }

    #[test]
    fn only_this_users_suspicious_items_can_be_switched_off() {
        assert!(can_disable(&item(ItemScope::User, Verdict::Warn)));
        assert!(can_disable(&item(ItemScope::User, Verdict::Bad)));
        assert!(!can_disable(&item(ItemScope::User, Verdict::Ok)));
        assert!(!can_disable(&item(ItemScope::User, Verdict::Unknown)));
        assert!(!can_disable(&item(ItemScope::System, Verdict::Bad)), "needs admin rights");
    }

    #[test]
    fn the_switch_off_plan_is_one_undoable_step() {
        let p = disable_plan(&item(ItemScope::User, Verdict::Warn)).unwrap();
        assert_eq!(p.steps.len(), 1);
        assert_eq!(p.steps[0].action, Action::DisableStartupItem { id: "file:/x".into() });
        assert!(p.steps[0].needs.is_none());
    }

    #[test]
    fn guard_places_are_the_three_quick_scan_targets() {
        let kinds: Vec<&str> = guard_places().iter().map(|g| g.kind).collect();
        assert_eq!(kinds, ["downloads", "zalo", "usb"]);
    }
}
