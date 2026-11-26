//! Quarantine: a detected file is moved into Genra's own folder, encoded so it cannot run or be
//! opened by accident, and can be put back for 30 days. Every item carries a small JSON record
//! (where it came from, why), written before the original is removed, so a crash never loses it.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

    /// Moves `path` into quarantine. The original is removed only after the encoded copy and its
    /// record are safely written.
    pub fn put(&self, path: &Path, reason: &str) -> Result<Item> {
        let mut bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let id = format!("{}-{}", now(), &sha256[..12]);
        let item = Item {
            id: id.clone(),
            original_path: std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
            sha256,
            size: bytes.len() as u64,
            reason: reason.to_string(),
            quarantined_at: now(),
        };
        encode(&mut bytes);
        std::fs::write(self.payload(&id), &bytes)?;
        std::fs::write(self.record(&id), serde_json::to_vec_pretty(&item)?)?;
        std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
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

    /// Puts the file back where it was. Refuses to overwrite a file that exists there now, and
    /// checks the content is still the one that was quarantined.
    pub fn restore(&self, id: &str) -> Result<PathBuf> {
        if id.contains(['/', '\\', '.']) {
            bail!("invalid quarantine id");
        }
        let item: Item = serde_json::from_slice(&std::fs::read(self.record(id)).context("no such quarantine item")?)?;
        if item.original_path.exists() {
            bail!("{} exists; not overwriting it", item.original_path.display());
        }
        let mut bytes = std::fs::read(self.payload(id))?;
        encode(&mut bytes);
        if hex::encode(Sha256::digest(&bytes)) != item.sha256 {
            bail!("quarantined copy is damaged; not restoring");
        }
        if let Some(parent) = item.original_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&item.original_path, &bytes)?;
        self.forget(id)?;
        Ok(item.original_path)
    }

    /// Deletes an item for good.
    pub fn forget(&self, id: &str) -> Result<()> {
        if id.contains(['/', '\\', '.']) {
            bail!("invalid quarantine id");
        }
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
        let item = q.put(&file, "test").unwrap();
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
        let item = q.put(&file, "test").unwrap();
        std::fs::write(&file, b"new file the user made").unwrap();
        assert!(q.restore(&item.id).is_err());
        assert!(q.restore("../escape").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
