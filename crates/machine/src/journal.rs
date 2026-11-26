//! The repair journal. Every change is written here *before* it is made, with what is needed to
//! undo it; a second line says how it ended. One file per group (`<group_id>.jsonl`, JSON lines,
//! append-only) under `<data_dir>/journal/`. A repair is one group, undone with one press.
//!
//! The journal also performs the changes, so the order "write down, then change" cannot be
//! skipped by a caller. The only changes that exist:
//!
//! - [`Change::Quarantine`]: a file moved into Genra's quarantine (`<data_dir>/quarantine/`).
//! - [`Change::CreateFile`]: a new file Genra wrote (a clean copy). It never replaces anything.
//! - [`Change::SetRegistryValue`] and [`Change::MoveRegistryValue`]: current-user registry only.
//!
//! Undo never overwrites a file that exists now and refuses when the state changed since the
//! change was made (a different hash, a different registry value). A group is checked as a
//! whole before anything in it is undone. Groups expire after [`KEEP_DAYS`], like quarantine.

use crate::reg::{self, RegValue};
use crate::{now, random_hex, sha256_hex};
use anyhow::{bail, Context, Result};
use genra_av_core::quarantine::Quarantine;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const KEEP_DAYS: u64 = genra_av_core::quarantine::KEEP_DAYS;

/// One change, with everything needed to undo it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    /// `path` (holding `sha256`) moved into quarantine. Undo puts it back, never over a file.
    Quarantine { path: PathBuf, sha256: String, reason: String },
    /// Genra wrote a new file at `path`. Undo moves it into quarantine if it still has `sha256`.
    CreateFile { path: PathBuf, sha256: String },
    /// A current-user registry value set to `new`; `previous` is `None` when it did not exist.
    SetRegistryValue { key: String, name: String, previous: Option<RegValue>, new: RegValue },
    /// A registry value moved from `key` to `backup_key` (same name): a startup entry switched off.
    MoveRegistryValue { key: String, name: String, value: RegValue, backup_key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EntryState {
    /// Written down; how it ended is not known (Genra stopped meanwhile). Undo checks what is there.
    Pending,
    Done,
    /// The change was not made (or was taken back by the step itself).
    Failed { error: String },
    Undone,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub id: String,
    pub group_id: String,
    /// Seconds since the Unix epoch.
    pub at: u64,
    pub change: Change,
    pub title_vi: String,
    pub title_en: String,
    pub state: EntryState,
    /// For [`Change::Quarantine`]: the quarantine item holding the original.
    pub quarantine_id: Option<String>,
}

/// A group as the history screen shows it.
#[derive(Debug, Clone, Serialize)]
pub struct Group {
    pub group_id: String,
    pub at: u64,
    pub entries: Vec<Entry>,
    /// Something in it is done and not undone yet, and it has not expired.
    pub can_undo: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UndoReport {
    pub group_id: String,
    pub undone: usize,
    pub title_vi: String,
    pub title_en: String,
    pub detail_vi: String,
    pub detail_en: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Line {
    Change { id: String, group_id: String, at: u64, change: Change, title_vi: String, title_en: String },
    Done { id: String, at: u64, #[serde(default, skip_serializing_if = "Option::is_none")] quarantine_id: Option<String> },
    Failed { id: String, at: u64, error: String },
    Undone { id: String, at: u64 },
}

pub struct Journal {
    dir: PathBuf,
    quarantine: Quarantine,
}

fn check_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid journal id {id:?}");
    }
    Ok(())
}

/// `path` with its folder resolved (links in the folder followed, the name itself kept), the
/// same form quarantine records, so paths from both can be compared.
pub(crate) fn resolved(path: &Path) -> PathBuf {
    match (path.parent().map(std::fs::canonicalize), path.file_name()) {
        (Some(Ok(dir)), Some(name)) => dir.join(name),
        _ => std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
    }
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn file_sha(path: &Path) -> Option<String> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() {
        return None;
    }
    std::fs::read(path).ok().map(|b| sha256_hex(&b))
}

/// Writes `bytes` to a new temporary file beside `dest` and links it into place, which fails
/// rather than replaces if anything is at `dest` (a file, a folder, a dangling link).
pub(crate) fn place_new(dest: &Path, bytes: &[u8]) -> Result<()> {
    let (Some(parent), Some(name)) = (dest.parent(), dest.file_name()) else { bail!("{} has no folder", dest.display()) };
    if exists(dest) {
        bail!("{} exists; not overwriting it", dest.display());
    }
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".genra-tmp-{}", random_hex(8)?));
    let tmp = parent.join(tmp_name);
    {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    let placed = match std::fs::hard_link(&tmp, dest) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(anyhow::anyhow!("{} appeared meanwhile; not overwriting it", dest.display())),
        // No hard links (FAT drives): create_new still never replaces what is at `dest`.
        Err(_) => std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .and_then(|mut f| f.write_all(bytes).and_then(|_| f.sync_all()))
            .with_context(|| format!("writing {}", dest.display())),
    };
    let _ = std::fs::remove_file(&tmp);
    placed
}

impl Journal {
    /// Opens the journal of the Genra data folder `data_dir`: lines go to `<data_dir>/journal/`,
    /// files moved aside to `<data_dir>/quarantine/` (the same quarantine the scanner uses).
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Journal> {
        let data_dir = data_dir.as_ref();
        let dir = data_dir.join("journal");
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let quarantine = Quarantine::open(data_dir.join("quarantine"))?;
        Ok(Journal { dir, quarantine })
    }

    pub fn quarantine(&self) -> &Quarantine {
        &self.quarantine
    }

    /// A fresh group id for a repair.
    pub fn new_group_id() -> Result<String> {
        random_hex(8)
    }

    fn group_file(&self, group_id: &str) -> PathBuf {
        self.dir.join(format!("{group_id}.jsonl"))
    }

    fn append(&self, group_id: &str, line: &Line) -> Result<()> {
        check_id(group_id)?;
        let mut text = serde_json::to_string(line)?;
        text.push('\n');
        let path = self.group_file(group_id);
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).with_context(|| format!("opening {}", path.display()))?;
        f.write_all(text.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
        f.sync_all()?;
        Ok(())
    }

    fn read_group(&self, path: &Path) -> Result<Vec<Entry>> {
        let text = std::fs::read_to_string(path)?;
        let mut entries: Vec<Entry> = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            // A torn last line (power cut mid-write) is skipped, never fatal.
            let Ok(line) = serde_json::from_str::<Line>(line) else { continue };
            match line {
                Line::Change { id, group_id, at, change, title_vi, title_en } => {
                    entries.push(Entry { id, group_id, at, change, title_vi, title_en, state: EntryState::Pending, quarantine_id: None })
                }
                Line::Done { id, quarantine_id, .. } => {
                    if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
                        e.state = EntryState::Done;
                        e.quarantine_id = quarantine_id.or(e.quarantine_id.take());
                    }
                }
                Line::Failed { id, error, .. } => {
                    if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
                        e.state = EntryState::Failed { error };
                    }
                }
                Line::Undone { id, .. } => {
                    if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
                        e.state = EntryState::Undone;
                    }
                }
            }
        }
        Ok(entries)
    }

    /// Every entry of every group, oldest first.
    pub fn entries(&self) -> Result<Vec<Entry>> {
        let mut all = Vec::new();
        for e in std::fs::read_dir(&self.dir)? {
            let p = e?.path();
            if p.extension().and_then(|x| x.to_str()) == Some("jsonl") {
                all.extend(self.read_group(&p).unwrap_or_default());
            }
        }
        all.sort_by(|a, b| (a.at, &a.group_id).cmp(&(b.at, &b.group_id)));
        Ok(all)
    }

    /// Entries of one group, in the order they were written.
    pub fn group(&self, group_id: &str) -> Result<Vec<Entry>> {
        check_id(group_id)?;
        let p = self.group_file(group_id);
        if !p.exists() {
            bail!("no repair with id {group_id}");
        }
        self.read_group(&p)
    }

    /// Groups, newest first.
    pub fn groups(&self) -> Result<Vec<Group>> {
        let mut groups: Vec<Group> = Vec::new();
        for e in self.entries()? {
            match groups.iter_mut().find(|g| g.group_id == e.group_id) {
                Some(g) => g.entries.push(e),
                None => groups.push(Group { group_id: e.group_id.clone(), at: e.at, entries: vec![e], can_undo: false }),
            }
        }
        let fresh = now().saturating_sub(KEEP_DAYS * 86_400);
        for g in &mut groups {
            g.can_undo = g.at >= fresh && g.entries.iter().any(|e| matches!(e.state, EntryState::Done | EntryState::Pending));
        }
        groups.sort_by_key(|g| std::cmp::Reverse(g.at));
        Ok(groups)
    }

    fn begin(&self, group_id: &str, change: Change, title_vi: &str, title_en: &str) -> Result<String> {
        let id = random_hex(8)?;
        self.append(group_id, &Line::Change { id: id.clone(), group_id: group_id.into(), at: now(), change, title_vi: title_vi.into(), title_en: title_en.into() })?;
        Ok(id)
    }

    fn end<T>(&self, group_id: &str, id: &str, r: Result<T>, quarantine_id: impl Fn(&T) -> Option<String>) -> Result<T> {
        match &r {
            Ok(v) => self.append(group_id, &Line::Done { id: id.into(), at: now(), quarantine_id: quarantine_id(v) })?,
            Err(e) => self.append(group_id, &Line::Failed { id: id.into(), at: now(), error: format!("{e:#}") })?,
        }
        r
    }

    /// Moves `path` into quarantine if it still holds `sha256`. Returns the quarantine item id.
    pub fn quarantine_file(&mut self, group_id: &str, path: &Path, sha256: &str, reason: &str, title_vi: &str, title_en: &str) -> Result<String> {
        let change = Change::Quarantine { path: resolved(path), sha256: sha256.to_ascii_lowercase(), reason: reason.into() };
        let id = self.begin(group_id, change, title_vi, title_en)?;
        let r = self.quarantine.put(path, sha256, reason).map(|item| item.id);
        self.end(group_id, &id, r, |qid| Some(qid.clone()))
    }

    /// Writes `bytes` as a new file at `dest`; fails if anything is there.
    pub fn create_file(&mut self, group_id: &str, dest: &Path, bytes: &[u8], title_vi: &str, title_en: &str) -> Result<()> {
        let change = Change::CreateFile { path: resolved(dest), sha256: sha256_hex(bytes) };
        let id = self.begin(group_id, change, title_vi, title_en)?;
        let r = place_new(dest, bytes);
        self.end(group_id, &id, r, |_| None)
    }

    /// Sets a current-user registry value, recording the one it replaces.
    pub fn set_registry_value(&mut self, group_id: &str, key: &str, name: &str, value: RegValue, title_vi: &str, title_en: &str) -> Result<()> {
        let previous = reg::get(key, name)?;
        let change = Change::SetRegistryValue { key: key.into(), name: name.into(), previous, new: value.clone() };
        let id = self.begin(group_id, change, title_vi, title_en)?;
        let r = reg::set(key, name, &value);
        self.end(group_id, &id, r, |_| None)
    }

    /// Moves a current-user registry value to `backup_key` (same name), refusing to overwrite a
    /// value already in the backup.
    pub fn move_registry_value(&mut self, group_id: &str, key: &str, name: &str, backup_key: &str, title_vi: &str, title_en: &str) -> Result<()> {
        let Some(value) = reg::get(key, name)? else { bail!("{key}\\{name} no longer exists") };
        if reg::get(backup_key, name)?.is_some() {
            bail!("{backup_key}\\{name} already holds a value; not overwriting it");
        }
        let change = Change::MoveRegistryValue { key: key.into(), name: name.into(), value: value.clone(), backup_key: backup_key.into() };
        let id = self.begin(group_id, change, title_vi, title_en)?;
        let r = reg::set(backup_key, name, &value).and_then(|_| match reg::delete_value(key, name) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = reg::delete_value(backup_key, name);
                Err(e)
            }
        });
        self.end(group_id, &id, r, |_| None)
    }

    /// The quarantine item holding an entry's file: from its "done" line, or (if Genra stopped
    /// before writing it) the item with the same origin and hash put there since the entry.
    fn find_quarantined(&self, e: &Entry) -> Option<String> {
        if let Some(id) = &e.quarantine_id {
            return Some(id.clone());
        }
        let Change::Quarantine { path, sha256, .. } = &e.change else { return None };
        self.quarantine
            .list()
            .ok()?
            .into_iter()
            .find(|i| &i.original_path == path && i.sha256.eq_ignore_ascii_case(sha256) && i.quarantined_at + 5 >= e.at)
            .map(|i| i.id)
    }

    /// Checks one entry can be undone. `freed` holds paths that undoing later entries of the
    /// same group will have emptied first. Returns `false` when there is nothing to undo.
    fn check(&self, e: &Entry, freed: &mut HashSet<PathBuf>) -> Result<bool> {
        if !matches!(e.state, EntryState::Done | EntryState::Pending) {
            return Ok(false);
        }
        if e.at + KEEP_DAYS * 86_400 < now() {
            bail!("this change is older than {KEEP_DAYS} days and can no longer be undone");
        }
        let pending = e.state == EntryState::Pending;
        match &e.change {
            Change::Quarantine { path, sha256, .. } => {
                let Some(qid) = self.find_quarantined(e) else {
                    if pending {
                        return Ok(false); // Never moved.
                    }
                    bail!("the original of {} is no longer in quarantine", path.display());
                };
                let item = self.quarantine.list()?.into_iter().find(|i| i.id == qid);
                let Some(item) = item else { bail!("the original of {} is no longer in quarantine", path.display()) };
                if !item.sha256.eq_ignore_ascii_case(sha256) {
                    bail!("the quarantined copy of {} is not the one Genra moved", path.display());
                }
                if exists(path) && !freed.contains(path) {
                    bail!("{} exists now; not overwriting it", path.display());
                }
                freed.remove(path);
                Ok(true)
            }
            Change::CreateFile { path, sha256 } => {
                if !exists(path) {
                    // Never written, or already removed by the user: nothing to take back.
                    freed.insert(path.clone());
                    return Ok(false);
                }
                match file_sha(path) {
                    Some(h) if h.eq_ignore_ascii_case(sha256) => {
                        freed.insert(path.clone());
                        Ok(true)
                    }
                    _ => bail!("{} changed since Genra wrote it; not touching it", path.display()),
                }
            }
            Change::SetRegistryValue { key, name, previous, new } => {
                let current = reg::get(key, name)?;
                if current.as_ref() == Some(new) {
                    Ok(previous.as_ref() != Some(new))
                } else if pending && current == *previous {
                    Ok(false)
                } else {
                    bail!("{key}\\{name} changed since; not touching it")
                }
            }
            Change::MoveRegistryValue { key, name, value, backup_key } => {
                let (here, backup) = (reg::get(key, name)?, reg::get(backup_key, name)?);
                match (here, backup) {
                    (None, Some(b)) if &b == value => Ok(true),
                    (Some(h), None) if pending && &h == value => Ok(false),
                    _ => bail!("{key}\\{name} changed since; not touching it"),
                }
            }
        }
    }

    fn apply(&mut self, e: &Entry) -> Result<()> {
        match &e.change {
            Change::Quarantine { path, .. } => {
                let qid = self.find_quarantined(e).context("not in quarantine")?;
                let back = self.quarantine.restore(&qid)?;
                debug_assert_eq!(&back, path);
            }
            Change::CreateFile { path, sha256 } => {
                self.quarantine.put(path, sha256, "Hoàn tác: bản sạch Genra đã tạo / undo: clean copy Genra wrote")?;
            }
            Change::SetRegistryValue { key, name, previous, .. } => match previous {
                Some(v) => reg::set(key, name, v)?,
                None => reg::delete_value(key, name)?,
            },
            Change::MoveRegistryValue { key, name, value, backup_key } => {
                reg::set(key, name, value)?;
                reg::delete_value(backup_key, name)?;
            }
        }
        self.append(&e.group_id, &Line::Undone { id: e.id.clone(), at: now() })
    }

    /// Undoes one change, after the same checks as a group.
    pub fn undo(&mut self, entry_id: &str) -> Result<()> {
        check_id(entry_id)?;
        let e = self.entries()?.into_iter().find(|e| e.id == entry_id).context("no such journal entry")?;
        if self.check(&e, &mut HashSet::new())? {
            self.apply(&e)?;
        } else if e.state == EntryState::Pending {
            self.append(&e.group_id, &Line::Undone { id: e.id.clone(), at: now() })?;
        }
        Ok(())
    }

    /// Undoes a whole repair, newest change first. Every change is checked before any is undone:
    /// if one cannot be (a file the user changed since, a file now where an original goes back),
    /// nothing is touched and the error says which.
    pub fn undo_group(&mut self, group_id: &str) -> Result<UndoReport> {
        let entries = self.group(group_id)?;
        let mut freed = HashSet::new();
        let mut todo = Vec::new();
        for e in entries.iter().rev() {
            if self.check(e, &mut freed)? {
                todo.push(e);
            }
        }
        let n = todo.len();
        for e in todo {
            self.apply(e).with_context(|| format!("undoing \"{}\"", e.title_en))?;
        }
        for e in entries.iter().filter(|e| e.state == EntryState::Pending) {
            if !matches!(self.group(group_id)?.iter().find(|x| x.id == e.id).map(|x| &x.state), Some(EntryState::Undone)) {
                self.append(group_id, &Line::Undone { id: e.id.clone(), at: now() })?;
            }
        }
        Ok(UndoReport {
            group_id: group_id.into(),
            undone: n,
            title_vi: "Đã hoàn tác".into(),
            title_en: "Undone".into(),
            detail_vi: format!("Genra đã đưa {n} thay đổi về như trước khi dọn. Tệp gốc đã về chỗ cũ."),
            detail_en: format!("Genra put {n} change(s) back the way they were before the repair. The original files are back where they were."),
        })
    }

    /// Deletes groups older than [`KEEP_DAYS`] (their quarantined files expire on their own).
    pub fn purge_expired(&self) -> Result<usize> {
        let cutoff = now().saturating_sub(KEEP_DAYS * 86_400);
        let mut n = 0;
        for e in std::fs::read_dir(&self.dir)? {
            let p = e?.path();
            if p.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let first = self.read_group(&p).ok().and_then(|v| v.first().map(|e| e.at));
            if first.is_some_and(|at| at < cutoff) {
                std::fs::remove_file(&p)?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// For tests: rewrite a group's timestamps to `at`.
    #[cfg(test)]
    pub(crate) fn backdate(&self, group_id: &str, at: u64) {
        let p = self.group_file(group_id);
        let text = std::fs::read_to_string(&p).unwrap();
        let out: Vec<String> = text
            .lines()
            .map(|l| {
                let mut v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["at"] = at.into();
                v.to_string()
            })
            .collect();
        std::fs::write(&p, out.join("\n") + "\n").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("genra-machine-j-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    fn lines(j: &Journal, g: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(j.group_file(g)).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn written_before_the_change_and_a_group_undone_in_one_go() {
        let root = tmp("group");
        let mut j = Journal::open(root.join("data")).unwrap();
        let g = Journal::new_group_id().unwrap();
        let a = root.join("a.xls");
        std::fs::write(&a, b"worm").unwrap();
        j.quarantine_file(&g, &a, &sha256_hex(b"worm"), "Kangatang", "Cách ly a.xls", "Quarantine a.xls").unwrap();
        j.create_file(&g, &a, b"clean", "Bản sạch", "Clean copy").unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"clean");

        let l = lines(&j, &g);
        let kinds: Vec<&str> = l.iter().map(|v| v["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["change", "done", "change", "done"], "each change is written before its outcome");
        assert_eq!(l[0]["change"]["type"], "quarantine");
        assert!(l[1]["quarantine_id"].is_string());

        let r = j.undo_group(&g).unwrap();
        assert_eq!(r.undone, 2);
        assert_eq!(std::fs::read(&a).unwrap(), b"worm", "original back");
        assert!(j.group(&g).unwrap().iter().all(|e| e.state == EntryState::Undone));
        assert_eq!(j.quarantine().list().unwrap().len(), 1, "the clean copy is kept in quarantine, not deleted");
        assert!(!j.groups().unwrap()[0].can_undo);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn undo_refuses_when_the_file_changed_and_touches_nothing() {
        let root = tmp("changed");
        let mut j = Journal::open(root.join("data")).unwrap();
        let g = Journal::new_group_id().unwrap();
        let a = root.join("a.xls");
        std::fs::write(&a, b"worm").unwrap();
        j.quarantine_file(&g, &a, &sha256_hex(b"worm"), "r", "t", "t").unwrap();
        j.create_file(&g, &a, b"clean", "t", "t").unwrap();
        std::fs::write(&a, b"the user typed new numbers into the clean copy").unwrap();
        let err = j.undo_group(&g).unwrap_err();
        assert!(format!("{err:#}").contains("changed since"), "{err:#}");
        assert_eq!(std::fs::read(&a).unwrap(), b"the user typed new numbers into the clean copy");
        assert_eq!(j.quarantine().list().unwrap().len(), 1, "original still safe in quarantine");
        assert!(j.groups().unwrap()[0].can_undo, "still undoable once the user moves their file");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn undo_never_overwrites_a_file_that_appeared() {
        let root = tmp("appeared");
        let mut j = Journal::open(root.join("data")).unwrap();
        let g = Journal::new_group_id().unwrap();
        let a = root.join("PERSONAL.xlsb");
        std::fs::write(&a, b"worm").unwrap();
        j.quarantine_file(&g, &a, &sha256_hex(b"worm"), "r", "t", "t").unwrap();
        std::fs::write(&a, b"a new file of the user's").unwrap();
        assert!(j.undo_group(&g).is_err());
        assert_eq!(std::fs::read(&a).unwrap(), b"a new file of the user's");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_pending_entry_is_undone_from_what_is_on_disk() {
        let root = tmp("pending");
        let mut j = Journal::open(root.join("data")).unwrap();
        let g = Journal::new_group_id().unwrap();
        let a = root.join("a.xls");
        std::fs::write(&a, b"worm").unwrap();
        // Genra stopped after moving the file but before writing "done".
        let change = Change::Quarantine { path: resolved(&a), sha256: sha256_hex(b"worm"), reason: "r".into() };
        j.begin(&g, change, "t", "t").unwrap();
        j.quarantine.put(&a, &sha256_hex(b"worm"), "r").unwrap();
        assert_eq!(j.group(&g).unwrap()[0].state, EntryState::Pending);
        j.undo_group(&g).unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"worm");
        // Stopped before moving anything: undo has nothing to do and says so.
        let g2 = Journal::new_group_id().unwrap();
        j.begin(&g2, Change::Quarantine { path: resolved(&a), sha256: sha256_hex(b"worm"), reason: "r".into() }, "t", "t").unwrap();
        assert_eq!(j.undo_group(&g2).unwrap().undone, 0);
        assert!(a.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn expired_groups_cannot_be_undone_and_are_purged() {
        let root = tmp("expiry");
        let mut j = Journal::open(root.join("data")).unwrap();
        let g = Journal::new_group_id().unwrap();
        let a = root.join("a.txt");
        j.create_file(&g, &a, b"x", "t", "t").unwrap();
        j.backdate(&g, now() - (KEEP_DAYS + 1) * 86_400);
        assert!(j.undo_group(&g).is_err());
        assert_eq!(j.purge_expired().unwrap(), 1);
        assert!(j.entries().unwrap().is_empty());
        assert!(a.exists(), "purging the journal never touches files");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn create_file_never_replaces_and_ids_are_checked() {
        let root = tmp("create");
        let mut j = Journal::open(root.join("data")).unwrap();
        let g = Journal::new_group_id().unwrap();
        let a = root.join("a.xlsx");
        std::fs::write(&a, b"user's").unwrap();
        assert!(j.create_file(&g, &a, b"clean", "t", "t").is_err());
        assert_eq!(std::fs::read(&a).unwrap(), b"user's");
        assert!(matches!(j.group(&g).unwrap()[0].state, EntryState::Failed { .. }));
        assert!(j.undo_group("../x").is_err());
        assert!(j.undo("zz").is_err());
        let leftovers = std::fs::read_dir(&root).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("genra-tmp")).count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_torn_last_line_is_skipped() {
        let root = tmp("torn");
        let mut j = Journal::open(root.join("data")).unwrap();
        let g = Journal::new_group_id().unwrap();
        j.create_file(&g, &root.join("a"), b"x", "t", "t").unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(j.group_file(&g)).unwrap();
        f.write_all(b"{\"kind\":\"change\",\"id\":\"ab").unwrap();
        assert_eq!(j.entries().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }
}
