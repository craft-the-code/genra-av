//! The quick scan: walk the places threats arrive, read only files that can carry code, skip
//! files already checked (same path, size and modified time), and collect what needs action.

use crate::reputation::Reputation;
use crate::rules::{Pack, Severity};
use crate::{targets, Report};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

/// Files bigger than this are not read by the quick scan (installers and disk images are hashed
/// by the guard when they arrive instead).
pub const MAX_FILE: u64 = 100 * 1024 * 1024;
const MAX_DEPTH: usize = 6;

/// What the scan cache remembers about one file. A file is skipped only when its size and
/// modified time (to the nanosecond) are unchanged *and* it was checked with the same rules
/// and engine; a change to the hash lists alone is checked from the stored SHA-256, without
/// reading the file again.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    size: u64,
    mtime_secs: u64,
    mtime_nanos: u32,
    verdict: Option<Severity>,
    sha256: String,
    rules: String,
    hashes: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Cache {
    /// Bumped when the entry layout changes; an old cache is dropped, not misread.
    #[serde(default)]
    format: u32,
    entries: HashMap<String, Entry>,
}

const CACHE_FORMAT: u32 = 2;

impl Cache {
    pub fn load(path: &Path) -> Cache {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Cache>(&b).ok())
            .filter(|c| c.format == CACHE_FORMAT)
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let out = Cache { format: CACHE_FORMAT, entries: self.entries.clone() };
        std::fs::write(path, serde_json::to_vec(&out).unwrap_or_default())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
    /// Cached files whose stored SHA-256 was looked up in new hash lists without a re-read.
    pub files_rechecked: u64,
    pub skipped_large: u64,
    pub hits: Vec<Hit>,
    /// The walk ended early because [`Walk::stop`] was set.
    pub stopped: bool,
}

pub struct Context<'a> {
    pub pack: Option<&'a Pack>,
    pub reputation: Option<&'a Reputation>,
    pub cache: Cache,
    rules_fp: String,
    hashes_fp: String,
}

/// Everything besides the hash lists that decides a verdict: the engine build and the pack's
/// rules, disabled ids and allow list. Deliberately not the pack version alone: a new pack
/// every few hours that only grows the hash lists must not force a full rescan.
fn rules_fingerprint(pack: Option<&Pack>, reputation: Option<&Reputation>) -> String {
    let mut h = Sha256::new();
    h.update(env!("CARGO_PKG_VERSION").as_bytes());
    h.update(crate::ENGINE.to_le_bytes());
    // YARA rules read the file's content: new rules mean reading files seen clean again.
    h.update(reputation.map(|r| r.yara_digest()).unwrap_or("").as_bytes());
    if let Some(p) = pack {
        h.update(serde_json::to_vec(&(&p.rules, &p.disabled, &p.allow_sha256)).unwrap_or_default());
    }
    hex::encode(h.finalize())
}

impl<'a> Context<'a> {
    pub fn new(pack: Option<&'a Pack>, reputation: Option<&'a Reputation>, cache: Cache) -> Context<'a> {
        let rules_fp = rules_fingerprint(pack, reputation);
        let hashes_fp = reputation.map(|r| r.fingerprint().to_string()).unwrap_or_default();
        Context { pack, reputation, cache, rules_fp, hashes_fp }
    }
}

/// Size and modified time with sub-second precision, of the file itself (never a link target).
fn stamp(path: &Path) -> Option<(u64, u64, u32)> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() {
        return None;
    }
    let t = md.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some((md.len(), t.as_secs(), t.subsec_nanos()))
}

/// Scans one file, using and updating the cache.
pub fn scan_file(ctx: &mut Context, path: &Path, summary: &mut Summary) {
    summary.files_seen += 1;
    let Some((size, secs, nanos)) = stamp(path) else { return };
    if size > MAX_FILE {
        summary.skipped_large += 1;
        return;
    }
    let k = path.to_string_lossy().into_owned();
    if let Some(e) = ctx.cache.entries.get_mut(&k) {
        let unchanged = e.size == size && e.mtime_secs == secs && e.mtime_nanos == nanos;
        let was_clean = e.verdict.is_none_or(|v| v < Severity::Suspicious);
        if unchanged && was_clean && e.rules == ctx.rules_fp {
            if e.hashes == ctx.hashes_fp {
                summary.files_cached += 1;
                return;
            }
            if ctx.reputation.and_then(|r| r.lookup(&e.sha256)).is_none() {
                e.hashes = ctx.hashes_fp.clone();
                summary.files_rechecked += 1;
                return;
            }
            // Newly listed: read it again to build the full report.
        }
    }
    let Ok(bytes) = std::fs::read(path) else { return };
    summary.files_read += 1;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let report = crate::scan_named(&name, &bytes, ctx.pack, ctx.reputation);
    ctx.cache.entries.insert(
        k,
        Entry {
            size,
            mtime_secs: secs,
            mtime_nanos: nanos,
            verdict: report.verdict,
            sha256: report.sha256.clone(),
            rules: ctx.rules_fp.clone(),
            hashes: ctx.hashes_fp.clone(),
        },
    );
    if report.verdict.is_some_and(|v| v >= Severity::Suspicious) {
        summary.hits.push(Hit { path: path.to_path_buf(), report });
    }
}

/// How deep a walk goes and what it leaves out.
pub struct Walk<'a> {
    pub max_depth: usize,
    /// Folders not walked into (compared exactly, e.g. `C:\Windows`), on top of
    /// [`targets::skip_dir`].
    pub skip: &'a [PathBuf],
    /// Checked before each folder; when set, the walk returns what it has so far.
    pub stop: Option<&'a AtomicBool>,
    /// Roots under which hidden folders are walked too (USB sticks).
    pub hidden_ok: &'a [PathBuf],
}

impl Walk<'_> {
    /// The quick scan: a few known folders, not deep.
    pub fn quick() -> Walk<'static> {
        Walk { max_depth: MAX_DEPTH, skip: &[], stop: None, hidden_ok: &[] }
    }
}

/// Deep enough for a whole drive or a folder the user picked.
pub const DEEP: usize = 24;

/// Walks `roots` (depth-limited, skipping heavy/hidden folders) and scans interesting files.
/// `progress` is called with each file path before it is considered.
pub fn walk(ctx: &mut Context, roots: &[PathBuf], progress: impl FnMut(&Path)) -> Summary {
    walk_with(ctx, roots, &Walk::quick(), progress)
}

/// [`walk`] with its depth, extra skipped folders and a stop flag given.
pub fn walk_with(ctx: &mut Context, roots: &[PathBuf], opts: &Walk, mut progress: impl FnMut(&Path)) -> Summary {
    let mut summary = Summary::default();
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        if opts.stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
            summary.stopped = true;
            break;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                let hidden_ok = opts.hidden_ok.iter().any(|r| path.starts_with(r));
                if depth < opts.max_depth && !targets::skip_dir_in(&path, hidden_ok) && !opts.skip.iter().any(|s| same_dir(s, &path)) {
                    stack.push((path, depth + 1));
                }
            } else if ft.is_file() && (targets::interesting(&path) || targets::in_startup_folder(&path)) {
                progress(&path);
                scan_file(ctx, &path, &mut summary);
            }
        }
    }
    summary
}

/// Windows paths compare without case; elsewhere exactly.
fn same_dir(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        a.as_os_str().to_string_lossy().eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
    } else {
        a == b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_with;
    use crate::reputation::HashList;
    use crate::rules::HashSetRef;

    fn tmp(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("genra-scan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn rep(contents: &[&[u8]], severity: Severity, trusted: bool) -> Reputation {
        let text: String = contents.iter().map(|c| format!("{}\n", hex::encode(Sha256::digest(c)))).collect();
        let list = HashList::from_bytes(&HashList::build_from_text(&text).unwrap()).unwrap();
        let r = HashSetRef { file: "t.bin".into(), sha256: String::new(), family: "TestFamily".into(), severity, source: "test".into(), trusted, count: None };
        Reputation::from_lists(vec![(r, list)])
    }

    fn pack(rules: &str) -> Pack {
        Pack::parse(format!(r#"{{"format":1,"version":1,"published":"x","rules":[{rules}]}}"#).as_bytes()).unwrap()
    }

    #[test]
    fn finds_known_bad_hash_and_caches_clean_files() {
        let root = tmp("basic");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/evil.exe"), b"MZ pretend malware").unwrap();
        std::fs::write(root.join("ok.docx"), b"not really a docx").unwrap();
        std::fs::write(root.join("photo.jpg"), b"skipped").unwrap();

        let rep = rep(&[b"MZ pretend malware"], Severity::Suspicious, false);
        let mut ctx = Context::new(None, Some(&rep), Cache::default());
        let s = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!((s.files_seen, s.files_read, s.hits.len()), (2, 2, 1));
        assert_eq!(s.hits[0].report.findings[0].family, "TestFamily");

        let again = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!((again.files_cached, again.files_read, again.hits.len()), (1, 1, 1), "clean cached, threat re-read");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_cached_clean_is_caught_by_a_new_hash_list_without_rereading_others() {
        let root = tmp("newlist");
        std::fs::write(root.join("a.exe"), b"later listed").unwrap();
        std::fs::write(root.join("b.exe"), b"stays clean").unwrap();
        let old = rep(&[b"something else"], Severity::Suspicious, false);
        let mut ctx = Context::new(None, Some(&old), Cache::default());
        assert!(walk(&mut ctx, std::slice::from_ref(&root), |_| {}).hits.is_empty());

        let new = rep(&[b"something else", b"later listed"], Severity::Suspicious, false);
        let mut ctx = Context::new(None, Some(&new), ctx.cache);
        let s = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!(s.hits.len(), 1, "newly listed file found");
        assert_eq!((s.files_read, s.files_rechecked), (1, 1), "clean file checked by stored hash, not read");

        let s = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!((s.files_cached, s.files_read), (1, 1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn new_yara_rules_read_files_seen_clean_again() {
        let root = tmp("newyara");
        std::fs::write(root.join("a.js"), b"var x = 'genra-yara-cache-marker';").unwrap();
        let none = Reputation::default();
        let mut ctx = Context::new(None, Some(&none), Cache::default());
        assert!(walk(&mut ctx, std::slice::from_ref(&root), |_| {}).hits.is_empty());
        let y = crate::yara::YaraRules::compile("rule Cache_Marker { strings: $a = \"genra-yara-cache-marker\" condition: $a }").unwrap();
        let with = Reputation::default().with_yara(y, "d1");
        let mut ctx = Context::new(None, Some(&with), ctx.cache);
        let s = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!((s.hits.len(), s.files_read), (1, 1), "read and scanned again, not just looked up by hash");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn new_rules_invalidate_the_cache_and_survive_a_save() {
        let root = tmp("newrules");
        std::fs::write(root.join("a.exe"), b"needle inside").unwrap();
        let sha = hex::encode(Sha256::digest(b"needle inside"));
        let p1 = pack("");
        let mut ctx = Context::new(Some(&p1), None, Cache::default());
        assert!(walk(&mut ctx, std::slice::from_ref(&root), |_| {}).hits.is_empty());
        let cache_file = root.join("cache.json");
        ctx.cache.save(&cache_file).unwrap();

        let p2 = pack(&format!(r#"{{"id":"r","family":"F","severity":"malware","message_vi":"m","when":{{"sha256_any":["{sha}"]}}}}"#));
        let mut ctx = Context::new(Some(&p2), None, Cache::load(&cache_file));
        assert_eq!(ctx.cache.len(), 1, "cache reloaded");
        let s = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!((s.files_read, s.hits.len()), (1, 1), "rule change forces a re-read");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn same_size_rewrite_within_a_second_is_seen() {
        let root = tmp("mtime");
        let f = root.join("a.exe");
        std::fs::write(&f, b"clean version!").unwrap();
        let rep = rep(&[b"bad1 version!!"], Severity::Suspicious, false);
        let mut ctx = Context::new(None, Some(&rep), Cache::default());
        walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        std::fs::write(&f, b"bad1 version!!").unwrap();
        let t = std::fs::metadata(&f).unwrap().modified().unwrap();
        let first = ctx.cache.entries.values().next().unwrap().clone();
        let d = t.duration_since(UNIX_EPOCH).unwrap();
        // Same second, different nanoseconds: second-precision caching would miss this rewrite.
        assert_eq!(first.size, 14);
        let mut forged = first.clone();
        forged.mtime_secs = d.as_secs();
        forged.mtime_nanos = d.subsec_nanos().wrapping_add(1) % 1_000_000_000;
        ctx.cache.entries.insert(f.to_string_lossy().into_owned(), forged);
        let s = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!(s.hits.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn xlstart_files_are_scanned_whatever_their_extension() {
        let root = tmp("xlstart");
        let xl = root.join("Excel").join("XLSTART");
        std::fs::create_dir_all(&xl).unwrap();
        std::fs::write(xl.join("PERSONAL"), b"worm body").unwrap();
        std::fs::write(root.join("PERSONAL"), b"worm body").unwrap();
        let rep = rep(&[b"worm body"], Severity::Suspicious, false);
        let mut ctx = Context::new(None, Some(&rep), Cache::default());
        let s = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!(s.hits.len(), 1, "only the copy in XLSTART");
        assert!(s.hits[0].path.starts_with(&xl));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hash_feed_hits_alone_never_quarantine_unless_trusted() {
        let bytes = b"listed file";
        let feed = rep(&[bytes], Severity::Malware, false);
        let r = scan_with(bytes, None, Some(&feed));
        assert_eq!(r.verdict, Some(Severity::Malware));
        assert!(!r.should_quarantine(), "untrusted feed: report, do not move");
        let curated = rep(&[bytes], Severity::Malware, true);
        assert!(scan_with(bytes, None, Some(&curated)).should_quarantine());
        let sha = hex::encode(Sha256::digest(bytes));
        let p = pack(&format!(r#"{{"id":"r","family":"F","severity":"malware","message_vi":"m","when":{{"sha256_any":["{sha}"]}}}}"#));
        assert!(scan_with(bytes, Some(&p), Some(&feed)).should_quarantine(), "a reviewed rule says malware");
    }

    #[test]
    fn walk_with_skips_named_folders_and_stops_when_asked() {
        let root = tmp("walk-with");
        let keep = root.join("keep");
        let sys = root.join("Windows");
        std::fs::create_dir_all(&keep).unwrap();
        std::fs::create_dir_all(&sys).unwrap();
        std::fs::write(keep.join("a.docx"), b"x").unwrap();
        std::fs::write(sys.join("b.docx"), b"x").unwrap();
        let mut ctx = Context::new(None, None, Cache::default());
        let skip = [sys.clone()];
        let opts = Walk { max_depth: DEEP, skip: &skip, stop: None, hidden_ok: &[] };
        let s = walk_with(&mut ctx, std::slice::from_ref(&root), &opts, |_| {});
        assert_eq!(s.files_seen, 1, "the skipped folder is not walked");
        assert!(!s.stopped);
        let stop = AtomicBool::new(true);
        let opts = Walk { max_depth: DEEP, skip: &[], stop: Some(&stop), hidden_ok: &[] };
        let s = walk_with(&mut ctx, std::slice::from_ref(&root), &opts, |_| {});
        assert!(s.stopped);
        assert_eq!(s.files_seen, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn hidden_folders_are_walked_only_under_allowed_roots() {
        let root = tmp("hidden-ok");
        let hid = root.join(".worm");
        std::fs::create_dir_all(&hid).unwrap();
        std::fs::write(hid.join("a.xls"), b"x").unwrap();
        let mut ctx = Context::new(None, None, Cache::default());
        let s = walk(&mut ctx, std::slice::from_ref(&root), |_| {});
        assert_eq!(s.files_seen, 0, "hidden folders are skipped by default");
        let ok = [root.clone()];
        let opts = Walk { max_depth: DEEP, skip: &[], stop: None, hidden_ok: &ok };
        let s = walk_with(&mut ctx, std::slice::from_ref(&root), &opts, |_| {});
        assert_eq!(s.files_seen, 1, "a USB root walks its hidden folders");
        let _ = std::fs::remove_dir_all(&root);
    }
}
