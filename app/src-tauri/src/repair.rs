//! "Dọn sạch giúp tôi" around the machine plan (`genra-av-machine`): check that the detected file
//! can be cleaned at all (if not, the window offers "Cách ly tệp này"), drop other infected files
//! the cleaner would refuse so they cannot roll the whole repair back, and turn the run report into
//! what the window shows. The journal does every change and every undo; nothing here writes files
//! except "Cách ly tệp này".

use crate::packs::Loaded;
use anyhow::{bail, Context, Result};
use genra_av_core::quarantine::Quarantine;
use genra_av_core::{clean, scan_named, Report};
use genra_av_machine::repair::{Action, Outcome, Plan, RunReport, StepState};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Why a repair did not happen. `refused` means the cleaner would not touch this file (the window
/// then offers only "Cách ly tệp này"); `failed` means something went wrong and nothing changed.
#[derive(Debug, Serialize)]
pub struct Failure {
    pub kind: &'static str,
    pub code: &'static str,
    pub detail: String,
}

impl Failure {
    pub fn failed(code: &'static str, e: impl std::fmt::Display) -> Failure {
        Failure { kind: "failed", code, detail: e.to_string() }
    }
}

/// Plain-word reason for a cleaner refusal; the window turns the code into a sentence.
fn refusal(e: &anyhow::Error) -> Failure {
    let msg = format!("{e:#}");
    let low = msg.to_ascii_lowercase();
    let code = if low.contains("not an office file") {
        "not_office"
    } else if low.contains("encrypted") {
        "encrypted"
    } else if low.contains("excel 4.0") || low.contains("macro sheet") || low.contains("xlm") || low.contains("auto_open") {
        "old_macros"
    } else if low.contains("over ") && low.contains("mb") {
        "too_large"
    } else if low.contains("not supported") {
        "unsupported"
    } else {
        "other"
    };
    Failure { kind: "refused", code, detail: msg }
}

pub fn quarantine(data: &Path) -> Result<Quarantine> {
    Quarantine::open(data.join("quarantine"))
}

fn read_checked(path: &Path) -> Result<Vec<u8>> {
    let md = std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !md.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if md.len() > clean::MAX_INPUT as u64 {
        bail!("{} is over {} MB", path.display(), clean::MAX_INPUT / 1024 / 1024);
    }
    Ok(std::fs::read(path)?)
}

/// The family shown for a finding: the most severe one's.
pub fn family_of(r: &Report) -> String {
    r.findings.iter().max_by_key(|f| f.severity).map(|f| f.family.clone()).unwrap_or_default()
}

/// The detected file as it is now: its report, after checking there is something to clean and
/// that the cleaner can make a macro-free copy of it.
pub fn precheck(rules: &Loaded, path: &Path) -> std::result::Result<Report, Failure> {
    let bytes = read_checked(path).map_err(|e| Failure::failed("read", e))?;
    // As the result screen showed it (Defender's answer is remembered for the session).
    let report = crate::quick::checked(scan_named(&crate::util::file_name(path), &bytes, Some(&rules.pack), Some(&rules.reputation)), path, rules);
    if report.verdict.is_none_or(|v| v < genra_av_core::rules::Severity::Suspicious) {
        return Err(Failure::failed("nothing_to_clean", "the file has no finding to clean"));
    }
    // A worm copy in Excel's startup folder is moved out, not cleaned, and anything that is not
    // an Office document (a shortcut, a script, an archive) is quarantined: no cleaner check.
    let in_xlstart = genra_av_core::targets::in_startup_folder(path) || path.parent().is_some_and(|d| genra_av_machine::repair::xlstart_dirs().iter().any(|x| x == d));
    if !in_xlstart && genra_av_machine::repair::is_office_document(path) {
        clean::clean(&bytes).map_err(|e| refusal(&e))?;
    }
    Ok(report)
}

/// Drops "clean this other file" steps the cleaner would refuse (an encrypted workbook, old
/// Excel 4.0 macros): one of them failing would roll back the whole repair. They stay where they
/// are and the next quick scan lists them with "Cách ly tệp này". The detected file itself is
/// checked by [`precheck`] before planning, so the first step is always kept (for a threat that goes to quarantine there is no `ReplaceWithClean` to drop).
pub fn keep_cleanable(plan: &mut Plan) {
    let mut first = true;
    plan.steps.retain(|s| {
        let keep = first || !matches!(&s.action, Action::ReplaceWithClean { path } if read_checked(path).and_then(|b| clean::clean(&b)).is_err());
        first = false;
        keep
    });
}

/// "Cách ly tệp này": moves the file aside (restorable for 30 days) after checking it is the one scanned.
pub fn quarantine_file(data: &Path, rules: &Loaded, path: &Path) -> std::result::Result<genra_av_core::quarantine::Item, Failure> {
    let bytes = read_checked(path).map_err(|e| Failure::failed("read", e))?;
    // The reason kept with the item is the one the result screen named (Defender's family too).
    let report = crate::quick::checked(scan_named(&crate::util::file_name(path), &bytes, Some(&rules.pack), Some(&rules.reputation)), path, rules);
    let q = quarantine(data).map_err(|e| Failure::failed("quarantine", e))?;
    q.put(path, &report.sha256, &family_of(&report)).map_err(|e| Failure::failed("quarantine", format!("{e:#}")))
}

/// A cleaned file on the done screen.
#[derive(Debug, Clone, Serialize)]
pub struct CleanedView {
    pub name: String,
    pub original_path: String,
    pub clean_name: String,
    pub clean_path: String,
    /// The clean copy has another extension (.xlsm → .xlsx).
    pub renamed: bool,
    pub removed: Vec<String>,
}

/// What the window shows for one press of "Dọn sạch giúp tôi" (or its automatic continuation).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RepairView {
    /// Every step done and verified. `group_id` is the "Hoàn tác" for the whole repair.
    Done {
        group_id: String,
        name: String,
        family: String,
        /// Workbooks taken out of Excel's startup folder (names only).
        xlstart: Vec<String>,
        cleaned: Vec<CleanedView>,
        /// Steps with nothing to do (already as wanted).
        skipped: usize,
        /// What was done on the machine besides the file (steps that were done, not skipped).
        machine: MachineDone,
        verified: bool,
        report: RunReport,
    },
    /// Nothing changed: Excel must close first. The plan waits under `group_id`.
    NeedsExcel { group_id: String, name: String, open_documents: Vec<String>, report: RunReport },
    /// A step failed; everything done before was undone (or, rarely, could not be).
    NotDone { name: String, rolled_back: bool, report: RunReport },
}

/// Counts for the done screen: programs stopped, startup entries switched off, Windows tools
/// unlocked, items on a USB stick shown again, and steps Windows did not allow (said once).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct MachineDone {
    pub stopped: usize,
    pub startup: usize,
    pub unlocked: usize,
    pub shown: usize,
    /// Machine steps that could not be done (admin rights, or Windows refused to stop it).
    pub left: usize,
}

fn machine_done(plan: &Plan, report: &RunReport) -> MachineDone {
    let mut m = MachineDone::default();
    for (s, r) in plan.steps.iter().zip(&report.steps) {
        let done = r.state == StepState::Done;
        let slot = match &s.action {
            Action::StopProcess { .. } => &mut m.stopped,
            Action::DisableStartupItem { .. } | Action::DisableThreatStartup { .. } | Action::DisableScheduledTask { .. } => &mut m.startup,
            Action::LiftLock { .. } => &mut m.unlocked,
            Action::Unhide { .. } => &mut m.shown,
            // A threat still running is left for after the restart: counted in `left` below.
            Action::QuarantineFile { .. } if r.state == StepState::NotAllowed => {
                m.left += 1;
                continue;
            }
            _ => continue,
        };
        if done {
            *slot += 1;
        } else if r.state == StepState::NotAllowed {
            m.left += 1;
        }
    }
    m
}

pub fn view(plan: &Plan, name: &str, family: &str, report: RunReport) -> RepairView {
    use crate::util::file_name;
    match &report.outcome {
        Outcome::Done => {
            let xlstart = plan
                .steps
                .iter()
                .zip(&report.steps)
                .filter(|(_, r)| r.state == StepState::Done)
                .filter_map(|(s, _)| match &s.action {
                    Action::RemoveXlstartItem { path } => Some(file_name(path)),
                    _ => None,
                })
                .collect();
            let cleaned = report
                .cleaned
                .iter()
                .map(|c| CleanedView {
                    name: file_name(&c.original_path),
                    original_path: c.original_path.to_string_lossy().into_owned(),
                    clean_name: file_name(&c.clean_path),
                    clean_path: c.clean_path.to_string_lossy().into_owned(),
                    renamed: c.clean_path != c.original_path,
                    removed: c.removed.clone(),
                })
                .collect();
            RepairView::Done {
                group_id: report.group_id.clone(),
                name: name.into(),
                family: family.into(),
                xlstart,
                cleaned,
                skipped: report.steps.iter().filter(|s| s.state == StepState::Skipped).count(),
                machine: machine_done(plan, &report),
                verified: report.verified,
                report,
            }
        }
        Outcome::NeedsAction { need } => {
            let genra_av_machine::repair::Need::CloseApp { open_documents, .. } = need;
            RepairView::NeedsExcel { group_id: report.group_id.clone(), name: name.into(), open_documents: open_documents.clone(), report }
        }
        Outcome::RolledBack { .. } => RepairView::NotDone { name: name.into(), rolled_back: true, report },
        Outcome::RollbackFailed { .. } => RepairView::NotDone { name: name.into(), rolled_back: false, report },
    }
}

/// Paths the window may reveal after a repair: the clean copies.
pub fn clean_paths(v: &RepairView) -> Vec<PathBuf> {
    match v {
        RepairView::Done { cleaned, .. } => cleaned.iter().map(|c| PathBuf::from(&c.clean_path)).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use genra_av_machine::repair::{Need, Step, StepResult};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("genra-app-repair-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn plan(actions: Vec<Action>) -> Plan {
        Plan {
            group_id: "0011223344556677".into(),
            steps: actions.into_iter().map(|action| Step { action, title_vi: "b".into(), title_en: "s".into(), needs: None }).collect(),
            summary_vi: String::new(),
            summary_en: String::new(),
        }
    }

    fn report(outcome: Outcome, states: &[StepState]) -> RunReport {
        RunReport {
            group_id: "0011223344556677".into(),
            outcome,
            steps: states
                .iter()
                .enumerate()
                .map(|(index, &state)| StepResult { index, title_vi: String::new(), title_en: String::new(), state, detail_vi: String::new(), detail_en: String::new(), error: None })
                .collect(),
            verified: true,
            cleaned: Vec::new(),
            title_vi: String::new(),
            title_en: String::new(),
            detail_vi: String::new(),
            detail_en: String::new(),
        }
    }

    #[test]
    fn refusals_get_plain_codes() {
        assert_eq!(refusal(&anyhow::anyhow!("not an Office file (neither OLE2 nor OOXML)")).code, "not_office");
        assert_eq!(refusal(&anyhow::anyhow!("workbook is encrypted")).code, "encrypted");
        assert_eq!(refusal(&anyhow::anyhow!("cannot make this file macro-free: Excel 4.0 macro sheet x")).code, "old_macros");
        assert_eq!(refusal(&anyhow::anyhow!("weird")).kind, "refused");
    }

    #[test]
    fn a_file_without_findings_is_left_alone() {
        let root = tmp("clean");
        let f = root.join("note.txt");
        std::fs::write(&f, b"hello").unwrap();
        let err = precheck(&crate::packs::bundled(), &f).unwrap_err();
        assert_eq!(err.code, "nothing_to_clean");
        assert_eq!(std::fs::read(&f).unwrap(), b"hello");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn other_files_the_cleaner_refuses_are_dropped_but_the_threat_is_kept() {
        let root = tmp("keep");
        let threat = root.join("a.xls");
        let other = root.join("b.xls");
        std::fs::write(&threat, b"not office").unwrap();
        std::fs::write(&other, b"not office either").unwrap();
        let x = root.join("XLSTART/mypersonnel.xls");
        let mut p = plan(vec![
            Action::ReplaceWithClean { path: threat.clone() },
            Action::RemoveXlstartItem { path: x.clone() },
            Action::ReplaceWithClean { path: other },
        ]);
        keep_cleanable(&mut p);
        let kept: Vec<&Action> = p.steps.iter().map(|s| &s.action).collect();
        assert_eq!(kept, [&Action::ReplaceWithClean { path: threat }, &Action::RemoveXlstartItem { path: x }]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_view_lists_the_worm_and_waits_for_excel() {
        let x = PathBuf::from("/h/Excel/mypersonnel.xls");
        let p = plan(vec![Action::ReplaceWithClean { path: "/d/a.xls".into() }, Action::RemoveXlstartItem { path: x }]);
        let v = view(&p, "a.xls", "Kangatang", report(Outcome::Done, &[StepState::Done, StepState::Done]));
        let RepairView::Done { xlstart, group_id, .. } = &v else { panic!("{v:?}") };
        assert_eq!(xlstart, &["mypersonnel.xls"]);
        assert_eq!(group_id, "0011223344556677");
        assert_eq!(serde_json::to_value(&v).unwrap()["state"], "done");

        let need = Outcome::NeedsAction { need: Need::CloseApp { app: "Excel".into(), open_documents: vec!["a.xls".into()] } };
        let v = view(&p, "a.xls", "Kangatang", report(need, &[]));
        assert!(matches!(&v, RepairView::NeedsExcel { open_documents, .. } if open_documents == &["a.xls"]));
        assert_eq!(serde_json::to_value(&v).unwrap()["state"], "needs_excel");

        let v = view(&p, "a.xls", "", report(Outcome::RolledBack { failed_step: 1, error: "x".into() }, &[StepState::Done, StepState::Failed]));
        assert!(matches!(v, RepairView::NotDone { rolled_back: true, .. }));
    }

    #[test]
    fn the_view_counts_what_was_done_on_the_machine() {
        let p = plan(vec![
            Action::StopProcess { pid: 1, started: "t".into(), path: "/x.js".into(), program: "wscript.exe".into(), image: false },
            Action::QuarantineFile { path: "/x.js".into(), expected_sha256: "00".into() },
            Action::DisableThreatStartup { id: "run:x".into() },
            Action::DisableScheduledTask { name: "\\x".into() },
            Action::LiftLock { key: "k".into(), name: "n".into() },
            Action::Unhide { path: "/u".into() },
        ]);
        let states = [StepState::Done, StepState::Done, StepState::Done, StepState::NotAllowed, StepState::Skipped, StepState::Done];
        let v = view(&p, "x.js", "", report(Outcome::Done, &states));
        let RepairView::Done { machine, .. } = &v else { panic!("{v:?}") };
        assert_eq!(machine, &MachineDone { stopped: 1, startup: 1, unlocked: 0, shown: 1, left: 1 });
        assert_eq!(serde_json::to_value(&v).unwrap()["machine"]["left"], 1);
    }
}
