//! `genra-av machine ...`: the machine repair engine from the command line (what the desktop app
//! calls). Text output by default, `--json` for machines.

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use genra_av_core::rules::{Pack, Severity};
use genra_av_machine::repair::{self, Need, Outcome, Plan, Scope, StepState};
use genra_av_machine::{health, startup, Journal};
use std::path::{Path, PathBuf};

/// The rules this binary was built with; used when `--rules` is not given.
static BUNDLED_PACK: &[u8] = include_bytes!("../../../rules/base.json");

#[derive(Args)]
pub struct PackArgs {
    /// Rule pack JSON (default: the rules bundled at build time).
    #[arg(long)]
    rules: Option<PathBuf>,
    #[arg(long)]
    pubkey: Option<PathBuf>,
    /// Load --rules without a signature. Development only.
    #[arg(long)]
    unsigned: bool,
}

#[derive(Subcommand)]
pub enum MachineCmd {
    /// Defender / Gatekeeper, updates, firewall, Office macro setting.
    Health {
        #[arg(long)]
        json: bool,
    },
    /// What starts with the computer, and which items look wrong.
    Startup {
        #[command(flatten)]
        pack: PackArgs,
        #[arg(long)]
        json: bool,
    },
    /// Print the "Dọn sạch giúp tôi" plan for a detected file. Changes nothing.
    Plan {
        file: PathBuf,
        #[command(flatten)]
        pack: PackArgs,
        #[arg(long)]
        json: bool,
    },
    /// Clean a detected file and the machine. Without --yes only prints the plan.
    Repair {
        file: PathBuf,
        /// Run the plan.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        pack: PackArgs,
        #[arg(long)]
        json: bool,
    },
    /// Past repairs, newest first.
    Journal {
        #[arg(long)]
        json: bool,
    },
    /// Undo a whole repair.
    Undo {
        group_id: String,
        #[arg(long)]
        json: bool,
    },
}

fn pack_of(a: &PackArgs) -> Result<Pack> {
    match &a.rules {
        Some(_) => Ok(super::load_pack(a.rules.as_deref(), a.pubkey.as_deref(), a.unsigned, true)?.expect("rules given")),
        None => Pack::parse(BUNDLED_PACK).context("bundled rules"),
    }
}

fn print_json(v: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn tag<T: std::fmt::Debug>(t: T) -> String {
    format!("{t:?}").to_uppercase()
}

fn plan_for(file: &Path, pack: &Pack) -> Result<Option<Plan>> {
    let size = std::fs::metadata(file).with_context(|| format!("reading {}", file.display()))?.len();
    if size > genra_av_core::clean::MAX_INPUT as u64 {
        bail!("{} is too large to clean", file.display());
    }
    let report = genra_av_core::scan(&std::fs::read(file)?, Some(pack));
    let has_macros = !report.vba_modules.is_empty() || report.verdict.is_some_and(|v| v >= Severity::Suspicious);
    if !has_macros {
        return Ok(None);
    }
    Ok(Some(repair::plan_for_threat_in(file, &report, &Scope::this_machine(Some(pack), None))))
}

fn print_plan(plan: &Plan) {
    println!("{}", plan.summary_vi);
    println!("  {}", plan.summary_en);
    for (i, s) in plan.steps.iter().enumerate() {
        println!("  {}. {}", i + 1, s.title_vi);
        println!("     {}", s.title_en);
        if let Some(Need::CloseApp { app, open_documents }) = &s.needs {
            println!("     needs: close {app} {open_documents:?}");
        }
    }
    println!("  repair id: {}", plan.group_id);
}

pub fn run(cmd: MachineCmd) -> Result<bool> {
    match cmd {
        MachineCmd::Health { json } => {
            let items = health::check();
            if json {
                print_json(&items)?;
            } else {
                for i in &items {
                    println!("{:<7} {}: {}", tag(i.status), i.title_vi, i.detail_vi);
                    println!("        {}: {}", i.title_en, i.detail_en);
                    if let Some(f) = i.fix {
                        println!("        fix: {f:?}");
                    }
                }
            }
            Ok(items.iter().any(|i| i.status == health::Status::Bad))
        }
        MachineCmd::Startup { pack, json } => {
            let pack = pack_of(&pack)?;
            let items = startup::list_with(Some(&pack), None);
            if json {
                print_json(&items)?;
            } else {
                for i in &items {
                    let sig = match (i.signed, &i.publisher) {
                        (Some(true), Some(p)) => format!("signed: {p}"),
                        (Some(true), None) => "signed".into(),
                        (Some(false), _) => "unsigned".into(),
                        (None, _) => "signature unknown".into(),
                    };
                    println!("{:<7} {} [{:?}, {}] {}", tag(i.verdict), i.name, i.scope, i.location, sig);
                    println!("        {}", i.command);
                    println!("        {}", i.reason_vi);
                }
                println!("{} item(s)", items.len());
            }
            Ok(items.iter().any(|i| i.verdict == startup::Verdict::Bad))
        }
        MachineCmd::Plan { file, pack, json } => {
            let pack = pack_of(&pack)?;
            match plan_for(&file, &pack)? {
                None => println!("Tệp này không có macro, không cần dọn. / This file has no macros; nothing to clean."),
                Some(plan) if json => print_json(&plan)?,
                Some(plan) => print_plan(&plan),
            }
            Ok(false)
        }
        MachineCmd::Repair { file, yes, pack, json } => {
            let pack = pack_of(&pack)?;
            let Some(plan) = plan_for(&file, &pack)? else {
                println!("Tệp này không có macro, không cần dọn. / This file has no macros; nothing to clean.");
                return Ok(false);
            };
            if !yes {
                if json {
                    print_json(&plan)?;
                } else {
                    print_plan(&plan);
                    println!("Nothing changed. Run again with --yes to do it.");
                }
                return Ok(false);
            }
            let mut journal = Journal::open(super::data_dir()?)?;
            let report = repair::run(&plan, &mut journal, |p| {
                if !json && p.state != StepState::Started {
                    eprintln!("[{}/{}] {:?}: {}", p.index + 1, p.total, p.state, p.title_en);
                }
            });
            if json {
                print_json(&report)?;
            } else {
                println!("{}", report.title_vi);
                println!("  {}", report.detail_vi);
                println!("  {}", report.title_en);
                println!("  {}", report.detail_en);
                for s in &report.steps {
                    println!("  {:?}  {}{}", s.state, s.title_en, s.error.as_ref().map(|e| format!(" ({e})")).unwrap_or_default());
                }
                for c in &report.cleaned {
                    println!("  clean copy: {}", c.clean_path.display());
                    for r in &c.removed {
                        println!("    removed {r}");
                    }
                    for k in &c.kept {
                        println!("    kept    {k}");
                    }
                }
                println!("  verified: {}; undo with: genra-av machine undo {}", report.verified, report.group_id);
            }
            match report.outcome {
                Outcome::Done => Ok(false),
                Outcome::NeedsAction { .. } => Ok(true),
                _ => bail!("the repair did not finish"),
            }
        }
        MachineCmd::Journal { json } => {
            let journal = Journal::open(super::data_dir()?)?;
            let groups = journal.groups()?;
            if json {
                print_json(&groups)?;
            } else {
                for g in &groups {
                    println!("{}  at {}  {}", g.group_id, g.at, if g.can_undo { "can be undone" } else { "undone or expired" });
                    for e in &g.entries {
                        println!("    {:<8} {}", format!("{:?}", e.state).split_whitespace().next().unwrap_or(""), e.title_en);
                    }
                }
                if groups.is_empty() {
                    println!("no repairs yet");
                }
            }
            Ok(false)
        }
        MachineCmd::Undo { group_id, json } => {
            let mut journal = Journal::open(super::data_dir()?)?;
            let r = journal.undo_group(&group_id)?;
            if json {
                print_json(&r)?;
            } else {
                println!("{}: {}", r.title_vi, r.detail_vi);
                println!("{}: {}", r.title_en, r.detail_en);
            }
            Ok(false)
        }
    }
}
