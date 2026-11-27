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
    /// The pack's YARA rules, compiled (they ship beside the pack like the lists).
    yara: Option<crate::yara::YaraRules>,
    /// Why the pack's YARA rules are not in use, when they are not (the hash lists still are).
    yara_error: Option<String>,
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

/// A YARA file name as the pack pipeline writes it: `yara-<12 hex>.yar`.
pub fn yara_file_name_ok(name: &str) -> bool {
    name.len() == 21 && name.starts_with("yara-") && name.ends_with(".yar") && name[5..17].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn load_yara(y: &crate::rules::YaraRef, dir: &Path) -> Result<(crate::yara::YaraRules, String)> {
    if !yara_file_name_ok(&y.file) {
        bail!("YARA rule file name {:?} is not yara-<sha12>.yar", y.file);
    }
    let bytes = std::fs::read(dir.join(&y.file)).with_context(|| format!("reading YARA rules {}", y.file))?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if !actual.eq_ignore_ascii_case(&y.sha256) || !y.file[5..17].eq_ignore_ascii_case(&actual[..12]) {
        bail!("YARA rules {} do not match the digest in the pack", y.file);
    }
    let source = std::str::from_utf8(&bytes).with_context(|| format!("YARA rules {} are not UTF-8", y.file))?;
    if crate::yara::count_rules(source) as u64 != y.rules {
        bail!("YARA rules {} hold {} rules, the pack says {}", y.file, crate::yara::count_rules(source), y.rules);
    }
    let rules = crate::yara::YaraRules::compile_with(source, y.malware.iter().cloned().collect())?;
    Ok((rules, actual))
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
        let mut rep = Reputation::from_lists(lists);
        if let Some(y) = &pack.yara {
            // A YARA problem (a damaged file, rules an older engine refuses) costs this layer
            // only: the hash lists stay in use.
            match load_yara(y, dir) {
                Ok((rules, digest)) => rep = rep.with_yara(rules, &digest),
                Err(e) => rep.yara_error = Some(format!("{e:#}")),
            }
        }
        Ok(rep)
    }

    /// Why the pack's YARA rules are not in use, if they are not.
    pub fn yara_error(&self) -> Option<&str> {
        self.yara_error.as_deref()
    }

    pub fn from_lists(lists: Vec<(HashSetRef, HashList)>) -> Reputation {
        let fingerprint = fingerprint(&lists);
        Reputation { lists, fingerprint, yara: None, yara_error: None }
    }

    /// Adds compiled YARA rules; `digest` (of their source) joins the fingerprint, so the scan
    /// cache looks at every file again when the rules change.
    pub fn with_yara(mut self, rules: crate::yara::YaraRules, digest: &str) -> Reputation {
        let mut h = Sha256::new();
        h.update(self.fingerprint.as_bytes());
        h.update(b"yara");
        h.update(digest.as_bytes());
        h.update(crate::yara::ENGINE.as_bytes());
        self.fingerprint = hex::encode(h.finalize());
        self.yara = Some(rules);
        self
    }

    pub fn yara(&self) -> Option<&crate::yara::YaraRules> {
        self.yara.as_ref()
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

    #[test]
    fn yara_rules_beside_the_pack_are_checked_compiled_and_used() {
        let dir = std::env::temp_dir().join(format!("genra-rep-yara-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = "rule Demo_Family_Marker { strings: $a = \"genra-yara-test-marker\" condition: $a }\n";
        let digest = hex::encode(Sha256::digest(src.as_bytes()));
        let file = format!("yara-{}.yar", &digest[..12]);
        std::fs::write(dir.join(&file), src).unwrap();
        let pack_with = |file: &str, sha: &str, rules: u64, malware: &str| {
            crate::rules::Pack::parse(
                format!(r#"{{"format":1,"version":1,"published":"t","yara":{{"file":"{file}","sha256":"{sha}","rules":{rules},"source":"test","malware":[{malware}]}}}}"#).as_bytes(),
            )
            .unwrap()
        };
        let rep = Reputation::load(&pack_with(&file, &digest, 1, ""), &dir).unwrap();
        assert_eq!(rep.yara().map(|y| y.len()), Some(1));
        assert!(rep.yara_error().is_none());
        assert_ne!(rep.fingerprint(), Reputation::default().fingerprint(), "rules change the cache fingerprint");
        let r = crate::scan_with(b"..genra-yara-test-marker..", None, Some(&rep));
        assert_eq!(r.findings.iter().map(|f| f.rule.as_str()).collect::<Vec<_>>(), ["yara.Demo_Family_Marker"]);
        assert_eq!(r.verdict, Some(crate::rules::Severity::Suspicious));
        assert!(!r.findings[0].auto_quarantine);
        // Only the signed pack's own list rates a rule malware.
        let rep_m = Reputation::load(&pack_with(&file, &digest, 1, r#""Demo_Family_Marker""#), &dir).unwrap();
        let r = crate::scan_with(b"..genra-yara-test-marker..", None, Some(&rep_m));
        assert_eq!((r.verdict, r.findings[0].auto_quarantine), (Some(crate::rules::Severity::Malware), true));
        // The pack's disabled list switches a rule off.
        let mut p = pack_with(&file, &digest, 1, "");
        p.disabled.push("yara.Demo_Family_Marker".into());
        assert!(crate::scan_with(b"..genra-yara-test-marker..", Some(&p), Some(&rep)).findings.is_empty());
        // A wrong digest, count or name costs the YARA layer only, never the whole pack.
        for bad in [pack_with(&file, &"0".repeat(64), 1, ""), pack_with(&file, &digest, 2, ""), pack_with("pack.json", &digest, 1, "")] {
            let rep = Reputation::load(&bad, &dir).unwrap();
            assert!(rep.yara().is_none() && rep.yara_error().is_some());
        }
        std::fs::write(dir.join(&file), "rule broken { condition: nope }\n").unwrap();
        let broken = hex::encode(Sha256::digest(b"rule broken { condition: nope }\n"));
        let f2 = format!("yara-{}.yar", &broken[..12]);
        std::fs::rename(dir.join(&file), dir.join(&f2)).unwrap();
        let rep = Reputation::load(&pack_with(&f2, &broken, 1, ""), &dir).unwrap();
        assert!(rep.yara().is_none() && rep.yara_error().unwrap().contains("compile"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
