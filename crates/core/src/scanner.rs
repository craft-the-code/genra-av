//! The quick scan: walk the places threats arrive, read only files that can carry code, skip
//! files already checked (same path, size and modified time), and collect what needs action.

use crate::reputation::Reputation;
use crate::rules::{Pack, Severity};
use crate::{scan_with, targets, Report};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Files bigger than this are not read by the quick scan (installers and disk images are hashed
/// by the guard when they arrive instead).
pub const MAX_FILE: u64 = 100 * 1024 * 1024;
const MAX_DEPTH: usize = 6;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Cache {
    /// path -> (size, mtime secs, verdict severity or none, sha256)
    entries: HashMap<String, (u64, u64, Option<Severity>, String)>,
}

impl Cache {
    pub fn load(path: &Path) -> Cache {
        std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, serde_json::to_vec(self).unwrap_or_default())
    }
}

#[derive(Debug, Serialize)]
pub struct Hit {
    pub path: PathBuf,
    pub report: Report,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub files_seen: u64,
    pub files_read: u64,
    pub files_cached: u64,
    pub skipped_large: u64,
    pub hits: Vec<Hit>,
}

pub struct Context<'a> {
    pub pack: Option<&'a Pack>,
    pub reputation: Option<&'a Reputation>,
    pub cache: Cache,
}

fn key(path: &Path) -> Option<(String, u64, u64)> {
    let md = std::fs::metadata(path).ok()?;
    let mtime = md.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some((path.to_string_lossy().into_owned(), md.len(), mtime))
}

/// Scans one file, using and updating the cache. Returns the report when the file was read.
pub fn scan_file(ctx: &mut Context, path: &Path, summary: &mut Summary) {
    summary.files_seen += 1;
    let Some((k, size, mtime)) = key(path) else { return };
    if size > MAX_FILE {
        summary.skipped_large += 1;
        return;
    }
    if let Some((s, m, verdict, _)) = ctx.cache.entries.get(&k) {
        if *s == size && *m == mtime && verdict.is_none_or(|v| v < Severity::Suspicious) {
            summary.files_cached += 1;
            return;
        }
    }
    let Ok(bytes) = std::fs::read(path) else { return };
    summary.files_read += 1;
    let report = scan_with(&bytes, ctx.pack, ctx.reputation);
    ctx.cache.entries.insert(k, (size, mtime, report.verdict, report.sha256.clone()));
    if report.verdict.is_some_and(|v| v >= Severity::Suspicious) {
        summary.hits.push(Hit { path: path.to_path_buf(), report });
    }
}

/// Walks `roots` (depth-limited, skipping heavy/hidden folders) and scans interesting files.
/// `progress` is called with each file path before it is considered.
pub fn walk(ctx: &mut Context, roots: &[PathBuf], mut progress: impl FnMut(&Path)) -> Summary {
    let mut summary = Summary::default();
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                let name = entry.file_name();
                if depth < MAX_DEPTH && !targets::skip_dir(&name.to_string_lossy()) {
                    stack.push((path, depth + 1));
                }
            } else if ft.is_file() && targets::interesting(&path) {
                progress(&path);
                scan_file(ctx, &path, &mut summary);
            }
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::HashList;
    use crate::rules::HashSetRef;
    use sha2::{Digest, Sha256};

    #[test]
    fn finds_known_bad_hash_and_caches_clean_files() {
        let root = std::env::temp_dir().join(format!("genra-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/evil.exe"), b"MZ pretend malware").unwrap();
        std::fs::write(root.join("ok.docx"), b"not really a docx").unwrap();
        std::fs::write(root.join("photo.jpg"), b"skipped").unwrap();

        let bad = Sha256::digest(b"MZ pretend malware");
        let list = HashList::from_bytes(&bad).unwrap();
        let rep = Reputation::from_lists(vec![(
            HashSetRef { file: "t.bin".into(), sha256: String::new(), family: "TestFamily".into(), severity: Severity::Malware, source: "test".into() },
            list,
        )]);
        let mut ctx = Context { pack: None, reputation: Some(&rep), cache: Cache::default() };
        let s = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!((s.files_seen, s.files_read, s.hits.len()), (2, 2, 1));
        assert_eq!(s.hits[0].report.findings[0].family, "TestFamily");

        let again = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!((again.files_cached, again.files_read, again.hits.len()), (1, 1, 1), "clean cached, threat re-read");
        let _ = std::fs::remove_dir_all(&root);
    }
}
