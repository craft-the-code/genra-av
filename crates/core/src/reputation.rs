//! Hash reputation: large lists of known-bad SHA-256 digests, shipped beside the signed pack.
//! A list is a binary file of sorted 32-byte digests, so a million entries is 32 MB, loads with
//! one read, and a lookup is a binary search. The pack's JSON names each list with its own
//! SHA-256, so the one signature over the JSON covers the lists too (ADR 0002).

use crate::rules::{HashSetRef, Pack};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

pub struct HashList {
    digests: Vec<[u8; 32]>,
}

impl HashList {
    /// Parses a `.bin` list: a multiple of 32 bytes, strictly ascending (sorted, no duplicates).
    pub fn from_bytes(bytes: &[u8]) -> Result<HashList> {
        if !bytes.len().is_multiple_of(32) {
            bail!("hash list length {} is not a multiple of 32", bytes.len());
        }
        let digests: Vec<[u8; 32]> = bytes.as_chunks::<32>().0.to_vec();
        if digests.windows(2).any(|w| w[0] >= w[1]) {
            bail!("hash list is not strictly sorted");
        }
        Ok(HashList { digests })
    }

    /// Builds a list from text with one hex SHA-256 per line (comments `#` and blanks ignored),
    /// such as abuse.ch MalwareBazaar's export. Returns the `.bin` bytes.
    pub fn build_from_text(text: &str) -> Result<Vec<u8>> {
        let mut digests: Vec<[u8; 32]> = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim().trim_matches('"');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let d: [u8; 32] = hex::decode(line)
                .with_context(|| format!("line {}: not hex", n + 1))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("line {}: not a SHA-256", n + 1))?;
            digests.push(d);
        }
        digests.sort_unstable();
        digests.dedup();
        Ok(digests.concat())
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    pub fn contains(&self, digest: &[u8; 32]) -> bool {
        self.digests.binary_search(digest).is_ok()
    }
}

/// All hash lists named by a pack, verified against the digests in the (signed) pack JSON.
#[derive(Default)]
pub struct Reputation {
    lists: Vec<(HashSetRef, HashList)>,
    fingerprint: String,
}

/// Identifies a set of lists by their content and how a match is treated, so the scan cache can
/// tell when a file checked earlier must be looked up again.
fn fingerprint(lists: &[(HashSetRef, HashList)]) -> String {
    let mut h = Sha256::new();
    for (r, l) in lists {
        h.update(Sha256::digest(l.digests.concat()));
        h.update(format!("{:?}{}", r.severity, r.trusted).as_bytes());
    }
    hex::encode(h.finalize())
}

impl Reputation {
    /// Loads every list the pack names from `dir`. A list whose bytes do not match the digest in
    /// the pack is refused: the signature over the JSON is what vouches for it.
    pub fn load(pack: &Pack, dir: &Path) -> Result<Reputation> {
        let mut lists = Vec::new();
        for r in &pack.hash_sets {
            if r.file.contains('/') || r.file.contains('\\') || r.file.starts_with('.') {
                bail!("hash list name {:?} must be a plain file name", r.file);
            }
            let bytes = std::fs::read(dir.join(&r.file)).with_context(|| format!("reading hash list {}", r.file))?;
            let actual = hex::encode(Sha256::digest(&bytes));
            if !actual.eq_ignore_ascii_case(&r.sha256) {
                bail!("hash list {} does not match the digest in the pack", r.file);
            }
            let list = HashList::from_bytes(&bytes)?;
            if r.count.is_some_and(|c| c != list.len() as u64) {
                bail!("hash list {} has {} entries, the pack says {}", r.file, list.len(), r.count.unwrap_or(0));
            }
            lists.push((r.clone(), list));
        }
        Ok(Reputation::from_lists(lists))
    }

    pub fn from_lists(lists: Vec<(HashSetRef, HashList)>) -> Reputation {
        let fingerprint = fingerprint(&lists);
        Reputation { lists, fingerprint }
    }

    /// Changes whenever any list's content or treatment changes.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn entries(&self) -> usize {
        self.lists.iter().map(|(_, l)| l.len()).sum()
    }

    /// The first list that knows this digest.
    pub fn lookup(&self, sha256_hex: &str) -> Option<&HashSetRef> {
        let d: [u8; 32] = hex::decode(sha256_hex).ok()?.try_into().ok()?;
        self.lists.iter().find(|(_, l)| l.contains(&d)).map(|(r, _)| r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_sorted_deduplicated_lists_and_finds_members() {
        let a = "a".repeat(64);
        let b = "0".repeat(63) + "1";
        let text = format!("# header\n{a}\n\n{b}\n{a}\n");
        let bin = HashList::build_from_text(&text).unwrap();
        assert_eq!(bin.len(), 64, "duplicate removed");
        let list = HashList::from_bytes(&bin).unwrap();
        assert!(list.contains(&hex::decode(&a).unwrap().try_into().unwrap()));
        assert!(!list.contains(&[7u8; 32]));
    }

    #[test]
    fn refuses_unsorted_or_ragged_lists() {
        let mut bin = vec![2u8; 32];
        bin.extend([1u8; 32]);
        assert!(HashList::from_bytes(&bin).is_err());
        assert!(HashList::from_bytes(&[0u8; 31]).is_err());
        assert!(HashList::build_from_text("nothex").is_err());
    }
}
