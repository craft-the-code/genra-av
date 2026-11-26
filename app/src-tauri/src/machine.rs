//! Seam for machine-level work: health checks, programs that start with the computer, repair
//! plans that reach beyond one file (the worm in Excel's startup folder, other infected files),
//! and asking Excel to close. The `genra-av-machine` crate implements [`Machine`]; until it is
//! wired in, [`Unavailable`] answers every call with [`NotAvailable`] and the window shows
//! "Sắp có". Swapping the implementation in `lib.rs` needs no change in the window.

use genra_av_core::Report;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// The feature is not in this build yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NotAvailable;

pub type MachineResult<T> = Result<T, NotAvailable>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Ok,
    Warn,
    Bad,
}

/// One step of a repair plan, in plain words ("Gỡ sâu khỏi Excel").
#[derive(Debug, Clone, Serialize)]
pub struct Step {
    pub title_vi: String,
    pub detail_vi: String,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub id: String,
    pub steps: Vec<Step>,
    /// Excel must be closed before the plan can run.
    pub needs_excel_closed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanOutcome {
    /// Journal group: one "Hoàn tác" undoes the whole plan.
    pub group_id: String,
    pub done: Vec<Step>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExcelStatus {
    pub running: bool,
    pub open_books: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthItem {
    pub id: String,
    pub tone: Tone,
    pub title_vi: String,
    pub detail_vi: String,
    /// The one fix this item offers ("Sửa giúp tôi"), when it has one.
    pub fix_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupItem {
    pub name: String,
    pub location: String,
    pub publisher: Option<String>,
    pub tone: Tone,
    pub detail_vi: String,
}

pub trait Machine: Send + Sync {
    fn plan_for_threat(&self, report: &Report, path: &Path) -> MachineResult<Plan>;
    fn run_plan(&self, plan: &Plan) -> MachineResult<PlanOutcome>;
    fn undo_group(&self, group_id: &str) -> MachineResult<()>;
    fn excel_status(&self) -> MachineResult<ExcelStatus>;
    fn ask_excel_to_close(&self) -> MachineResult<()>;
    fn health(&self) -> MachineResult<Vec<HealthItem>>;
    fn startup(&self) -> MachineResult<Vec<StartupItem>>;
}

/// Every call: not available yet.
pub struct Unavailable;

impl Machine for Unavailable {
    fn plan_for_threat(&self, _: &Report, _: &Path) -> MachineResult<Plan> {
        Err(NotAvailable)
    }
    fn run_plan(&self, _: &Plan) -> MachineResult<PlanOutcome> {
        Err(NotAvailable)
    }
    fn undo_group(&self, _: &str) -> MachineResult<()> {
        Err(NotAvailable)
    }
    fn excel_status(&self) -> MachineResult<ExcelStatus> {
        Err(NotAvailable)
    }
    fn ask_excel_to_close(&self) -> MachineResult<()> {
        Err(NotAvailable)
    }
    fn health(&self) -> MachineResult<Vec<HealthItem>> {
        Err(NotAvailable)
    }
    fn startup(&self) -> MachineResult<Vec<StartupItem>> {
        Err(NotAvailable)
    }
}

/// What "Máy của bạn" renders: each part is either data or `null` (not available yet).
#[derive(Debug, Serialize)]
pub struct Overview {
    pub health: Option<Vec<HealthItem>>,
    pub startup: Option<Vec<StartupItem>>,
    pub excel: Option<ExcelStatus>,
}

pub fn overview(m: &dyn Machine) -> Overview {
    Overview { health: m.health().ok(), startup: m.startup().ok(), excel: m.excel_status().ok() }
}
