//! "Quét nhanh máy": walks the places threats arrive with the persisted scan cache, reporting the
//! folder and the file count as it goes. Before each folder it checks whether reading it is stuck
//! (on macOS the first read of Downloads, Desktop or Documents waits for the permission prompt),
//! so the window can say so instead of spinning.

use crate::packs::Loaded;
use crate::ScanResult;
use genra_av_core::rules::Severity;
use genra_av_core::scanner::{self, Cache, Summary};
use genra_av_machine::defender::{self, Budget, Outcome};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const PERMISSION_WAIT: Duration = Duration::from_secs(3);

const EMIT_EVERY: Duration = Duration::from_millis(120);

#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    /// `walking`, `waiting` while a folder read is blocked (permission prompt), or `defender`
    /// while Windows Defender is asked about a suspicious file (`folder` is then that file).
    pub phase: &'static str,
    pub folder: String,
    pub files: u64,
}

#[derive(Debug, Serialize)]
pub struct QuickResult {
    pub at: i64,
    /// `quick`, `full` or `folder`.
    pub scope: &'static str,
    /// The user pressed "Dừng": the result covers only what was walked.
    pub stopped: bool,
    pub files_seen: u64,
    pub files_read: u64,
    pub files_cached: u64,
    pub roots: Vec<String>,
    pub hits: Vec<ScanResult>,
}

/// Reads `dir` on a helper thread; if that has not returned after [`PERMISSION_WAIT`], calls
/// `waiting` once, then waits for it (the user answers the prompt, or it fails).
fn probe(dir: &Path, waiting: impl FnOnce()) {
    let (tx, rx) = mpsc::channel();
    let d = dir.to_path_buf();
    std::thread::spawn(move || {
        let _ = std::fs::read_dir(&d).map(|rd| rd.take(1).count());
        let _ = tx.send(());
    });
    if rx.recv_timeout(PERMISSION_WAIT).is_err() {
        waiting();
        let _ = rx.recv();
    }
}

/// Hits on public hash feeds alone are "Đáng ngờ": they never move a file by themselves. A hit on
/// the graded, trusted list is not "hash only" in this sense: it is malware (ADR 0004).
pub fn hash_only(r: &genra_av_core::Report) -> bool {
    let serious: Vec<_> = r.findings.iter().filter(|f| f.severity >= Severity::Suspicious).collect();
    !serious.is_empty() && serious.iter().all(|f| f.rule.starts_with("hash.") && !f.auto_quarantine)
}

/// The report as the app acts on it: scanned, then the safety rails (a validly signed program is
/// never quarantined on a hash match alone), then Windows Defender's opinion when Genra calls
/// the file suspicious (ADR 0004, layer 4).
pub fn checked(report: genra_av_core::Report, path: &Path, rules: &Loaded) -> genra_av_core::Report {
    checked_with(report, path, rules, true).0
}

/// [`checked`] without asking Defender (an answer it already gave is still used): for the folder
/// guard, since Defender watches new files itself.
pub fn checked_quiet(report: genra_av_core::Report, path: &Path, rules: &Loaded) -> genra_av_core::Report {
    checked_with(report, path, rules, false).0
}

/// [`checked`], asking Defender only when `defender` is true. Also says what asking did.
fn checked_with(mut report: genra_av_core::Report, path: &Path, rules: &Loaded, defender: bool) -> (genra_av_core::Report, Outcome) {
    genra_av_machine::rails::signed_file_rail(&mut report, path);
    let disabled = &rules.pack.disabled;
    // Past the scan's budget, an answer Defender already gave is still used: it costs nothing.
    let outcome = if defender { defender::second_opinion(&mut report, path, disabled) } else { defender::remembered_opinion(&mut report, path, disabled) };
    (report, outcome)
}

/// What to walk and how: the folders, their depth and skips, and the stop flag.
pub struct Job<'a> {
    pub scope: &'static str,
    pub roots: &'a [PathBuf],
    pub walk: scanner::Walk<'a>,
}

pub fn run_job(data: &Path, rules: &Loaded, job: &Job, emit: impl Fn(Progress)) -> QuickResult {
    let roots = job.roots;
    let cache_path = data.join("scan-cache.json");
    let mut ctx = scanner::Context::new(Some(&rules.pack), Some(&rules.reputation), Cache::load(&cache_path));
    let mut total = Summary::default();
    let mut seen = 0u64;
    let mut stopped = false;
    for root in roots {
        if stopped {
            break;
        }
        let folder = root.to_string_lossy().into_owned();
        emit(Progress { phase: "walking", folder: folder.clone(), files: seen });
        probe(root, || emit(Progress { phase: "waiting", folder: folder.clone(), files: seen }));
        let mut last = Instant::now();
        let s = scanner::walk_with(&mut ctx, std::slice::from_ref(root), &job.walk, |p| {
            seen += 1;
            if last.elapsed() >= EMIT_EVERY {
                last = Instant::now();
                let folder = p.parent().unwrap_or(p).to_string_lossy().into_owned();
                emit(Progress { phase: "walking", folder, files: seen });
            }
        });
        total.files_seen += s.files_seen;
        total.files_read += s.files_read;
        total.files_cached += s.files_cached + s.files_rechecked;
        total.hits.extend(s.hits);
        stopped = s.stopped;
    }
    let _ = std::fs::create_dir_all(data);
    let _ = ctx.cache.save(&cache_path);
    // A few files at most, two minutes in all, none after one failure or "Dừng"; the rest keep
    // Genra's own verdict and are asked about when the user opens them.
    let mut budget = Budget::new();
    let hits = total
        .hits
        .into_iter()
        .map(|h| {
            let size = std::fs::metadata(&h.path).map(|m| m.len()).unwrap_or(0);
            let ask = budget.open(job.walk.stop);
            if ask && cfg!(windows) && defender::enabled(&rules.pack.disabled) && defender::wants(&h.report, &h.path) {
                emit(Progress { phase: "defender", folder: h.path.to_string_lossy().into_owned(), files: seen });
            }
            let (report, outcome) = checked_with(h.report, &h.path, rules, ask);
            budget.record(outcome);
            let hash_only = hash_only(&report);
            ScanResult { name: crate::util::file_name(&h.path), path: h.path.to_string_lossy().into_owned(), size, hash_only, report }
        })
        .collect();
    QuickResult {
        at: crate::util::now(),
        scope: job.scope,
        stopped,
        files_seen: total.files_seen,
        files_read: total.files_read,
        files_cached: total.files_cached,
        roots: roots.iter().map(|r| r.to_string_lossy().into_owned()).collect(),
        hits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn run(data: &Path, rules: &Loaded, roots: &[PathBuf], emit: impl Fn(Progress)) -> QuickResult {
        run_job(data, rules, &Job { scope: "quick", roots, walk: scanner::Walk::quick() }, emit)
    }

    #[test]
    fn walks_reports_progress_and_keeps_the_cache() {
        let root = std::env::temp_dir().join(format!("genra-app-quick-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let docs = root.join("Downloads");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("a.docx"), b"not really a docx").unwrap();
        std::fs::write(docs.join("b.txt"), b"skipped").unwrap();
        let data = root.join("data");
        let events = Mutex::new(Vec::new());
        let r = run(&data, &crate::packs::bundled(), std::slice::from_ref(&docs), |p| events.lock().unwrap().push(p));
        assert_eq!(r.files_seen, 1);
        assert!(r.hits.is_empty());
        assert!(events.lock().unwrap().iter().all(|p| p.phase == "walking"));
        assert!(data.join("scan-cache.json").exists());
        let again = run(&data, &crate::packs::bundled(), &[docs], |_| {});
        assert_eq!(again.files_cached, 1, "second run uses the cache");
        let _ = std::fs::remove_dir_all(&root);
    }
}
