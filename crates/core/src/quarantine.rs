//! Quarantine: a detected file is moved into Genra's own folder, encoded so it cannot run or be
//! opened by accident, and can be put back for 30 days. Every item carries a small JSON record
//! (where it came from, why), written before the original is removed, so a crash never loses it.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const KEY: &[u8] = b"GENRA-AV-QUARANTINE";
pub const KEEP_DAYS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub original_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub reason: String,
    /// Seconds since the Unix epoch.
    pub quarantined_at: u64,
}

pub struct Quarantine {
    dir: PathBuf,
}

fn encode(bytes: &mut [u8]) {
    for (i, b) in bytes.iter_mut().enumerate() {
        *b ^= KEY[i % KEY.len()];
    }
}

fn check_id(id: &str) -> Result<()> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        bail!("invalid quarantine id");
    }
    Ok(())
}

/// 128 random bits, so two items never share an id, even for identical files in one second.
fn random_id() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("no system randomness: {e}"))?;
    Ok(hex::encode(b))
}

/// Writes a file that must not exist yet, and flushes it to disk.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Makes the new directory entries durable (Unix; on Windows the file flush is enough).
fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    let _ = dir;
    Ok(())
}

/// The file opened is the one whose metadata was checked (no swap for a link in between).
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        b.is_file() && a.len() == b.len()
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Quarantine {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Quarantine> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Quarantine { dir })
    }

    fn payload(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.bin"))
    }

    fn record(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Moves `path` into quarantine. `expected_sha256` is the digest the scan saw: if the file
    /// changed since, nothing is moved. Links are never followed. The encoded copy and its record
    /// are written with `create_new` under a random id and flushed to disk before the original is
    /// removed; if the removal fails, both are taken back out.
    pub fn put(&self, path: &Path, expected_sha256: &str, reason: &str) -> Result<Item> {
        let md = std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if !md.file_type().is_file() {
            bail!("{} is not a regular file (links are not followed); not quarantining", path.display());
        }
        let mut file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
        if !same_file(&md, &file.metadata()?) {
            bail!("{} changed while opening it; not quarantining", path.display());
        }
        let mut bytes = Vec::with_capacity(md.len() as usize);
        file.read_to_end(&mut bytes).with_context(|| format!("reading {}", path.display()))?;
        drop(file);
        let sha256 = hex::encode(Sha256::digest(&bytes));
        if !sha256.eq_ignore_ascii_case(expected_sha256) {
            bail!("{} changed since it was scanned; not quarantining", path.display());
        }
        let id = random_id()?;
        let original_path = match (path.parent().map(std::fs::canonicalize), path.file_name()) {
            (Some(Ok(dir)), Some(name)) => dir.join(name),
            _ => std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
        };
        let item = Item { id: id.clone(), original_path, sha256, size: bytes.len() as u64, reason: reason.to_string(), quarantined_at: now() };
        encode(&mut bytes);
        let (payload, record) = (self.payload(&id), self.record(&id));
        let written = write_new(&payload, &bytes).and_then(|_| write_new(&record, &serde_json::to_vec_pretty(&item)?)).and_then(|_| sync_dir(&self.dir));
        if let Err(e) = written {
            let _ = std::fs::remove_file(&record);
            let _ = std::fs::remove_file(&payload);
            return Err(e.context("writing the quarantine copy"));
        }
        if let Err(e) = std::fs::remove_file(path) {
            let _ = std::fs::remove_file(&record);
            let _ = std::fs::remove_file(&payload);
            return Err(anyhow::Error::new(e).context(format!("removing {} (left in place)", path.display())));
        }
        Ok(item)
    }

    pub fn list(&self) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        for e in std::fs::read_dir(&self.dir)? {
            let p = e?.path();
            if p.extension().and_then(|x| x.to_str()) == Some("json") {
                if let Ok(item) = serde_json::from_slice::<Item>(&std::fs::read(&p)?) {
                    items.push(item);
                }
            }
        }
        items.sort_by_key(|a| std::cmp::Reverse(a.quarantined_at));
        Ok(items)
    }

    /// Puts the file back where it was. Refuses if anything (a file, a folder, even a dangling
    /// link) is at that path now, and checks the content is still the one quarantined. The bytes
    /// go to a new temporary file beside the target, then are linked into place, which fails
    /// rather than replaces if something appeared there meanwhile.
    pub fn restore(&self, id: &str) -> Result<PathBuf> {
        check_id(id)?;
        let item: Item = serde_json::from_slice(&std::fs::read(self.record(id)).context("no such quarantine item")?)?;
        let target = &item.original_path;
        if std::fs::symlink_metadata(target).is_ok() {
            bail!("{} exists; not overwriting it", target.display());
        }
        let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
            bail!("{} has no folder to restore into", target.display());
        };
        let mut bytes = std::fs::read(self.payload(id))?;
        encode(&mut bytes);
        if hex::encode(Sha256::digest(&bytes)) != item.sha256 {
            bail!("quarantined copy is damaged; not restoring");
        }
        std::fs::create_dir_all(parent)?;
        if std::fs::symlink_metadata(parent)?.file_type().is_symlink() {
            bail!("{} is a link; not restoring through it", parent.display());
        }
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(format!(".genra-restore-{}", random_id()?));
        let tmp = parent.join(tmp_name);
        write_new(&tmp, &bytes)?;
        let placed = match std::fs::hard_link(&tmp, target) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(anyhow::anyhow!("{} appeared meanwhile; not overwriting it", target.display())),
            // File systems without hard links (FAT USB sticks): create_new still never follows
            // or replaces whatever is at the target.
            Err(_) => write_new(target, &bytes),
        };
        let _ = std::fs::remove_file(&tmp);
        placed?;
        self.forget(id)?;
        Ok(item.original_path)
    }

    /// Deletes an item for good.
    pub fn forget(&self, id: &str) -> Result<()> {
        check_id(id)?;
        let _ = std::fs::remove_file(self.payload(id));
        std::fs::remove_file(self.record(id)).context("no such quarantine item")?;
        Ok(())
    }

    /// Deletes items older than `KEEP_DAYS`. Returns how many went.
    pub fn purge_expired(&self) -> Result<usize> {
        let cutoff = now().saturating_sub(Duration::from_secs(KEEP_DAYS * 86_400).as_secs());
        let old: Vec<_> = self.list()?.into_iter().filter(|i| i.quarantined_at < cutoff).collect();
        for i in &old {
            self.forget(&i.id)?;
        }
        Ok(old.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("genra-q-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn put_list_restore_round_trip() {
        let root = tmp("rt");
        let file = root.join("bad.xls");
        std::fs::write(&file, b"pretend macro worm").unwrap();
        let q = Quarantine::open(root.join("q")).unwrap();
        let item = q.put(&file, &sha(b"pretend macro worm"), "test").unwrap();
        assert!(!file.exists(), "original removed");
        let stored = std::fs::read(q.payload(&item.id)).unwrap();
        assert_ne!(stored, b"pretend macro worm", "stored encoded");
        assert_eq!(q.list().unwrap().len(), 1);
        let back = q.restore(&item.id).unwrap();
        assert_eq!(std::fs::read(back).unwrap(), b"pretend macro worm");
        assert!(q.list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn restore_never_overwrites_and_rejects_path_ids() {
        let root = tmp("ow");
        let file = root.join("a.doc");
        std::fs::write(&file, b"one").unwrap();
        let q = Quarantine::open(root.join("q")).unwrap();
        let item = q.put(&file, &sha(b"one"), "test").unwrap();
        std::fs::write(&file, b"new file the user made").unwrap();
        assert!(q.restore(&item.id).is_err());
        assert!(q.restore("../escape").is_err());
        assert!(q.restore("a.b").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    #[test]
    fn identical_files_in_the_same_second_get_their_own_items() {
        let root = tmp("same");
        let q = Quarantine::open(root.join("q")).unwrap();
        let (a, b) = (root.join("a.xls"), root.join("b.xls"));
        std::fs::write(&a, b"same worm").unwrap();
        std::fs::write(&b, b"same worm").unwrap();
        let ia = q.put(&a, &sha(b"same worm"), "t").unwrap();
        let ib = q.put(&b, &sha(b"same worm"), "t").unwrap();
        assert_ne!(ia.id, ib.id);
        let mut origins: Vec<_> = q.list().unwrap().into_iter().map(|i| i.original_path).collect();
        origins.sort();
        assert_eq!(origins.len(), 2, "first original not lost");
        assert_eq!(q.restore(&ia.id).unwrap().file_name().unwrap(), "a.xls");
        assert_eq!(q.restore(&ib.id).unwrap().file_name().unwrap(), "b.xls");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn put_refuses_a_changed_file() {
        let root = tmp("changed");
        let q = Quarantine::open(root.join("q")).unwrap();
        let f = root.join("a.xls");
        std::fs::write(&f, b"user saved new content").unwrap();
        assert!(q.put(&f, &sha(b"what the scan saw"), "t").is_err());
        assert!(f.exists(), "left alone");
        assert!(q.list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn put_rolls_back_when_the_original_cannot_be_removed() {
        let root = tmp("rollback");
        let q = Quarantine::open(root.join("q")).unwrap();
        let locked = root.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        let f = locked.join("a.xls");
        std::fs::write(&f, b"worm").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let r = q.put(&f, &sha(b"worm"), "t");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(r.is_err());
        assert!(f.exists(), "original still there");
        assert!(std::fs::read_dir(root.join("q")).unwrap().next().is_none(), "record and payload taken back");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn links_are_never_followed() {
        let root = tmp("links");
        let q = Quarantine::open(root.join("q")).unwrap();
        let real = root.join("real.xls");
        std::fs::write(&real, b"worm").unwrap();
        let link = root.join("link.xls");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(q.put(&link, &sha(b"worm"), "t").is_err(), "put refuses a link");
        assert!(real.exists() && link.exists());

        let item = q.put(&real, &sha(b"worm"), "t").unwrap();
        // Someone plants a dangling link where the file was, pointing somewhere else.
        let elsewhere = root.join("elsewhere.txt");
        std::os::unix::fs::symlink(&elsewhere, &real).unwrap();
        assert!(q.restore(&item.id).is_err(), "restore refuses a dangling link");
        assert!(!elsewhere.exists(), "nothing written through the link");
        std::fs::remove_file(&real).unwrap();
        assert_eq!(std::fs::read(q.restore(&item.id).unwrap()).unwrap(), b"worm");
        let leftovers: Vec<_> = std::fs::read_dir(&root).unwrap().flatten().map(|e| e.file_name()).filter(|n| n.to_string_lossy().contains("genra-restore")).collect();
        assert!(leftovers.is_empty(), "temp file cleaned up");
        let _ = std::fs::remove_dir_all(&root);
    }
}
