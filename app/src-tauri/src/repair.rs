//! File-level repair behind "Dọn sạch giúp tôi": write a macro-free copy with the core cleaner,
//! move the original into quarantine, put the clean copy in its place, scan it again, and keep a
//! record so "Hoàn tác" can bring the original back. Machine-level steps (Excel startup folder,
//! other infected files) come from the `machine` seam once that crate lands.

use crate::packs::Loaded;
use crate::util::{file_name, new_id, now};
use anyhow::{bail, Context, Result};
use genra_av_core::quarantine::Quarantine;
use genra_av_core::rules::Severity;
use genra_av_core::{clean, scan_with, Report};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub at: i64,
    pub original_path: PathBuf,
    pub clean_path: PathBuf,
    pub clean_sha256: String,
    pub original_sha256: String,
    pub quarantine_id: String,
}

#[derive(Debug, Serialize)]
pub struct Done {
    pub id: String,
    pub name: String,
    pub clean_path: String,
    pub clean_name: String,
    /// The clean copy has another extension than the original (.xlsm → .xlsx).
    pub renamed: bool,
    pub removed: Vec<String>,
    pub kept: Vec<String>,
    pub quarantine_id: String,
    pub family: String,
}

/// Why a repair did not happen. `refused` means the cleaner would not touch this file (the window
/// then offers only "Cách ly tệp này"); `failed` means something went wrong and nothing changed.
#[derive(Debug, Serialize)]
pub struct Failure {
    pub kind: &'static str,
    pub code: &'static str,
    pub detail: String,
}

impl Failure {
    fn failed(code: &'static str, e: impl std::fmt::Display) -> Failure {
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

fn repairs_dir(data: &Path) -> PathBuf {
    data.join("repairs")
}

pub fn quarantine(data: &Path) -> Result<Quarantine> {
    Quarantine::open(data.join("quarantine"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Puts `tmp` at `dest` without replacing anything that is there (hard link, else a checked rename).
fn place(tmp: &Path, dest: &Path) -> Result<()> {
    match std::fs::hard_link(tmp, dest) {
        Ok(()) => {
            let _ = std::fs::remove_file(tmp);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => bail!("{} exists; not replacing it", dest.display()),
        Err(_) => {
            if std::fs::symlink_metadata(dest).is_ok() {
                bail!("{} exists; not replacing it", dest.display());
            }
            std::fs::rename(tmp, dest).with_context(|| format!("writing {}", dest.display()))
        }
    }
}

fn top_family(r: &Report) -> String {
    r.findings.iter().max_by_key(|f| f.severity).map(|f| f.family.clone()).unwrap_or_default()
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

/// Cleans `path` in place. On any failure after the original was moved aside, it is put back.
pub fn run(data: &Path, rules: &Loaded, path: &Path) -> std::result::Result<Done, Failure> {
    let bytes = read_checked(path).map_err(|e| Failure::failed("read", e))?;
    let report = scan_with(&bytes, Some(&rules.pack), Some(&rules.reputation));
    if report.verdict.is_none_or(|v| v < Severity::Suspicious) {
        return Err(Failure::failed("nothing_to_clean", "the file has no finding to clean"));
    }
    let cleaned = clean::clean(&bytes).map_err(|e| refusal(&e))?;
    let q = quarantine(data).map_err(|e| Failure::failed("quarantine", e))?;
    let parent = path.parent().ok_or_else(|| Failure::failed("read", "no parent folder"))?;
    let ext_now = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase());
    let dest = match cleaned.new_extension {
        Some(e) if ext_now.as_deref() != Some(e) => path.with_extension(e),
        _ => path.to_path_buf(),
    };
    if dest != path && std::fs::symlink_metadata(&dest).is_ok() {
        return Err(Failure::failed("dest_exists", format!("{} exists", dest.display())));
    }
    let id = new_id();
    let tmp = parent.join(format!(".{}.genra-clean-{id}", file_name(path)));
    write_new(&tmp, &cleaned.bytes).map_err(|e| Failure::failed("write", e))?;
    let family = top_family(&report);
    let item = match q.put(path, &report.sha256, &family) {
        Ok(i) => i,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Failure::failed("quarantine", format!("{e:#}")));
        }
    };
    let rollback = |dest_written: bool, code: &'static str, e: String| {
        if dest_written {
            let _ = std::fs::remove_file(&dest);
        }
        let _ = std::fs::remove_file(&tmp);
        let back = q.restore(&item.id).map(|_| ()).map_err(|e| format!("; putting the original back failed too: {e:#}"));
        Failure::failed(code, format!("{e}{}", back.err().unwrap_or_default()))
    };
    if let Err(e) = place(&tmp, &dest) {
        return Err(rollback(false, "write", format!("{e:#}")));
    }
    // Verify: the copy in place parses and carries no macro or finding any more.
    let after = match std::fs::read(&dest) {
        Ok(b) => b,
        Err(e) => return Err(rollback(true, "verify", e.to_string())),
    };
    let check = scan_with(&after, Some(&rules.pack), Some(&rules.reputation));
    if check.verdict.is_some_and(|v| v >= Severity::Suspicious) || !check.vba_modules.is_empty() {
        return Err(rollback(true, "verify", "the clean copy still has a finding".into()));
    }
    let record = Record {
        id: id.clone(),
        at: now(),
        original_path: item.original_path.clone(),
        clean_path: dest.clone(),
        clean_sha256: hex::encode(Sha256::digest(&after)),
        original_sha256: report.sha256.clone(),
        quarantine_id: item.id.clone(),
    };
    let saved = std::fs::create_dir_all(repairs_dir(data))
        .map_err(anyhow::Error::from)
        .and_then(|_| crate::util::write_atomic(&repairs_dir(data).join(format!("{id}.json")), &serde_json::to_vec_pretty(&record)?));
    if let Err(e) = saved {
        return Err(rollback(true, "write", format!("{e:#}")));
    }
    Ok(Done {
        id,
        name: file_name(path),
        clean_path: dest.to_string_lossy().into_owned(),
        clean_name: file_name(&dest),
        renamed: dest != path,
        removed: cleaned.removed,
        kept: cleaned.kept,
        quarantine_id: item.id,
        family,
    })
}

fn check_id(id: &str) -> Result<()> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        bail!("invalid repair id");
    }
    Ok(())
}

/// Brings the original back and removes the clean copy, but only if the copy is unchanged since
/// the repair (the user's later edits are never deleted). Returns where the original went.
pub fn undo(data: &Path, id: &str) -> std::result::Result<PathBuf, Failure> {
    check_id(id).map_err(|e| Failure::failed("not_found", e))?;
    let rec_path = repairs_dir(data).join(format!("{id}.json"));
    let rec: Record = std::fs::read(&rec_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| Failure::failed("not_found", "no such repair"))?;
    let q = quarantine(data).map_err(|e| Failure::failed("quarantine", e))?;
    let clean = &rec.clean_path;
    let aside = match std::fs::symlink_metadata(clean) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Failure::failed("read", e)),
        Ok(md) if !md.is_file() => return Err(Failure::failed("clean_changed", "the clean copy is no longer a plain file")),
        Ok(_) => {
            let bytes = std::fs::read(clean).map_err(|e| Failure::failed("read", e))?;
            if !hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(&rec.clean_sha256) {
                return Err(Failure::failed("clean_changed", "the clean copy was edited after the repair"));
            }
            let aside = clean.with_file_name(format!(".{}.genra-undo-{id}", file_name(clean)));
            std::fs::rename(clean, &aside).map_err(|e| Failure::failed("write", e))?;
            Some(aside)
        }
    };
    match q.restore(&rec.quarantine_id) {
        Ok(p) => {
            if let Some(a) = aside {
                let _ = std::fs::remove_file(a);
            }
            let _ = std::fs::remove_file(&rec_path);
            Ok(p)
        }
        Err(e) => {
            if let Some(a) = aside {
                let _ = std::fs::rename(a, clean);
            }
            Err(Failure::failed("restore", format!("{e:#}")))
        }
    }
}

/// "Cách ly tệp này": moves the file aside (restorable for 30 days) after checking it is the one scanned.
pub fn quarantine_file(data: &Path, rules: &Loaded, path: &Path) -> std::result::Result<genra_av_core::quarantine::Item, Failure> {
    let bytes = read_checked(path).map_err(|e| Failure::failed("read", e))?;
    let report = scan_with(&bytes, Some(&rules.pack), Some(&rules.reputation));
    let q = quarantine(data).map_err(|e| Failure::failed("quarantine", e))?;
    q.put(path, &report.sha256, &top_family(&report)).map_err(|e| Failure::failed("quarantine", format!("{e:#}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("genra-app-repair-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Sets up what a finished repair leaves behind: original in quarantine, clean copy in place.
    fn repaired(root: &Path) -> (PathBuf, PathBuf, String) {
        let data = root.join("data");
        let file = root.join("a.xls");
        std::fs::write(&file, b"original").unwrap();
        let q = quarantine(&data).unwrap();
        let item = q.put(&file, &hex::encode(Sha256::digest(b"original")), "Kangatang").unwrap();
        std::fs::write(&file, b"clean").unwrap();
        let rec = Record {
            id: "r1".into(),
            at: 0,
            original_path: item.original_path.clone(),
            clean_path: item.original_path.clone(),
            clean_sha256: hex::encode(Sha256::digest(b"clean")),
            original_sha256: item.sha256.clone(),
            quarantine_id: item.id,
        };
        std::fs::create_dir_all(repairs_dir(&data)).unwrap();
        std::fs::write(repairs_dir(&data).join("r1.json"), serde_json::to_vec(&rec).unwrap()).unwrap();
        (data, item.original_path, "r1".into())
    }

    #[test]
    fn undo_restores_the_original_and_removes_the_clean_copy() {
        let root = tmp("undo");
        let (data, file, id) = repaired(&root);
        assert_eq!(undo(&data, &id).unwrap(), file);
        assert_eq!(std::fs::read(&file).unwrap(), b"original");
        assert!(quarantine(&data).unwrap().list().unwrap().is_empty());
        assert_eq!(undo(&data, &id).unwrap_err().code, "not_found", "only once");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn undo_never_deletes_a_clean_copy_the_user_edited() {
        let root = tmp("edited");
        let (data, file, id) = repaired(&root);
        std::fs::write(&file, b"clean, then edited").unwrap();
        assert_eq!(undo(&data, &id).unwrap_err().code, "clean_changed");
        assert_eq!(std::fs::read(&file).unwrap(), b"clean, then edited");
        assert_eq!(quarantine(&data).unwrap().list().unwrap().len(), 1, "original still kept");
        assert!(undo(&data, "../x").is_err());
        let _ = std::fs::remove_dir_all(&root);
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
        let err = run(&root.join("data"), &crate::packs::bundled(), &f).unwrap_err();
        assert_eq!(err.code, "nothing_to_clean");
        assert_eq!(std::fs::read(&f).unwrap(), b"hello");
        let _ = std::fs::remove_dir_all(&root);
    }
}
