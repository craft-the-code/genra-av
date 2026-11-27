//! Rule packs: detection logic shipped as data, so a new threat is caught by publishing a pack,
//! not by releasing the app. A pack is JSON plus a detached Ed25519 signature; the app only
//! loads packs signed by a key it was built with (docs/adr/0002-signed-rule-packs.md).

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PACK_FORMAT: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pack {
    pub format: u32,
    /// Monotonic: a client refuses a pack older than the one it has (rollback protection).
    pub version: u64,
    pub published: String,
    /// After this moment the pack is refused (freeze protection: an attacker who can block
    /// updates cannot keep a client on an old pack forever). RFC 3339 (`2026-12-10T06:00:00Z`)
    /// or Unix seconds. Covered by the signature like every other field. Optional for unsigned
    /// development packs; [`Pack::verified`] requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Expiry>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Files we know are fine though a rule matches them: the false-positive kill switch.
    #[serde(default)]
    pub allow_sha256: Vec<String>,
    /// Rule ids switched off without shipping a new rule set.
    #[serde(default)]
    pub disabled: Vec<String>,
    /// Binary hash lists shipped beside this JSON (see `reputation`). Each is named with its
    /// SHA-256, so the signature over this JSON covers them.
    #[serde(default)]
    pub hash_sets: Vec<HashSetRef>,
    /// YARA rules for malware families shipped beside this JSON (see `yara`), named by digest
    /// like the hash lists. Older clients ignore the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yara: Option<YaraRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRef {
    /// Plain file name next to the pack, e.g. `yara-0123abcd.yar`.
    pub file: String,
    pub sha256: String,
    /// Number of `rule` declarations, checked on load.
    pub rules: u64,
    /// Where the rules come from and under which licences, e.g. "YARA Forge core + ReversingLabs".
    pub source: String,
    /// The YARA Forge release and ReversingLabs commit the file was built from (the signing job
    /// refuses to go back to older ones).
    #[serde(default)]
    pub forge_tag: String,
    #[serde(default)]
    pub rl_commit: String,
    /// Rules rated malware (quarantined without asking): reviewed in this repository
    /// (rules/yara-malware.json), never read from rule text. Every other match is suspicious.
    #[serde(default)]
    pub malware: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSetRef {
    /// Plain file name next to the pack, e.g. `malwarebazaar-recent.bin`.
    pub file: String,
    pub sha256: String,
    /// Family label shown when a file matches, e.g. "Known malware (MalwareBazaar)".
    pub family: String,
    /// Defaults to `suspicious`: anyone can upload a file to a public feed, including a clean,
    /// widely used one, so a hash match alone is a warning, not a verdict.
    #[serde(default = "suspicious")]
    pub severity: Severity,
    /// Where the hashes come from, e.g. "abuse.ch MalwareBazaar (CC0)".
    pub source: String,
    /// Only a graded list is `trusted` (scripts/hash_grade.py: a listed commodity family,
    /// corroborated by other engines, 48 hours old, re-checked by the signing job); only then may a
    /// hash match alone move a file into quarantine, and never a validly signed program (the
    /// signed-file rail). Raw feeds such as MalwareBazaar stay `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trusted: bool,
    /// Number of digests in the list, checked on load; lets the publisher refuse a shrinking list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

fn suspicious() -> Severity {
    Severity::Suspicious
}

/// A moment in time, written either as RFC 3339 or as Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Expiry(pub i64);

impl Serialize for Expiry {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for Expiry {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Secs(i64),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Secs(s) => Ok(Expiry(s)),
            Raw::Text(t) => parse_rfc3339(&t).map(Expiry).ok_or_else(|| serde::de::Error::custom(format!("expires {t:?} is not RFC 3339"))),
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)` to Unix seconds. Fractions are dropped.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok())?
    };
    let (y, mo, d, h, mi, sec) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        rest = &frac[n..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) && &rest[3..4] == ":" => {
            let oh: i64 = rest[1..3].parse().ok()?;
            let om: i64 = rest[4..6].parse().ok()?;
            let o = oh * 3600 + om * 60;
            if rest.starts_with('-') { -o } else { o }
        }
        _ => return None,
    };
    // Days from civil (H. Hinnant), proleptic Gregorian.
    let (y, m) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + sec - offset)
}

/// Seconds since the Unix epoch, now.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Suspicious,
    Malware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub family: String,
    pub severity: Severity,
    /// Shown to the user, Vietnamese first.
    pub message_vi: String,
    /// The same message in English, shown when the app's language is English. Optional so packs
    /// written before it existed still load; the app falls back to `message_vi`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_en: Option<String>,
    #[serde(default)]
    pub when: When,
    /// Where this threat persists on the machine, so "Dọn sạch giúp tôi" also cleans there. The
    /// only value so far is `xlstart` (Excel's startup folders). Repairs are a fixed list in
    /// `genra-av-machine`; a rule can only point at one of them, never add a new kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_persistence: Option<String>,
}

/// Every condition that is set must hold; a rule with no condition never matches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct When {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sha256_any: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vba_module_name_any: Vec<String>,
    /// Case-insensitive substrings that must all appear in one module's source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vba_source_all: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vba_source_any: Vec<String>,
}

impl Pack {
    pub fn parse(json: &[u8]) -> Result<Pack> {
        let pack: Pack = serde_json::from_slice(json).context("rule pack is not valid JSON")?;
        if pack.format != PACK_FORMAT {
            bail!("rule pack format {} is not supported (this build reads {})", pack.format, PACK_FORMAT);
        }
        Ok(pack)
    }

    /// Parses only after the signature over the exact bytes checks out against one of `keys`,
    /// and refuses a pack with no `expires` or one that has expired.
    pub fn verified(json: &[u8], sig_hex: &str, keys: &[VerifyingKey]) -> Result<Pack> {
        Pack::verified_at(json, sig_hex, keys, unix_now())
    }

    /// [`Pack::verified`] with an explicit clock (Unix seconds).
    pub fn verified_at(json: &[u8], sig_hex: &str, keys: &[VerifyingKey], now: i64) -> Result<Pack> {
        let pack = Pack::signature_checked(json, sig_hex, keys)?;
        match pack.expires {
            None => bail!("signed rule pack has no `expires`; refusing it"),
            Some(Expiry(e)) if now >= e => bail!("rule pack version {} expired (expires {e}, now {now})", pack.version),
            Some(_) => Ok(pack),
        }
    }

    /// Checks the signature only, ignoring expiry. For publishers inspecting an older pack
    /// (the CI reads the previous pack this way); clients use [`Pack::verified`].
    pub fn signature_checked(json: &[u8], sig_hex: &str, keys: &[VerifyingKey]) -> Result<Pack> {
        let sig_bytes: [u8; 64] = hex::decode(sig_hex.trim())
            .context("signature is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature is not 64 bytes"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        if !keys.iter().any(|k| k.verify_strict(json, &sig).is_ok()) {
            bail!("rule pack signature does not match any trusted key");
        }
        Pack::parse(json)
    }
}

/// Public keys the official packs are signed with (keys/*.pub). `pack-2` is the standby key, so
/// the signing key can be rotated without an app release (ADR 0002).
pub const TRUSTED_PACK_KEYS: [&str; 2] = [include_str!("../../../keys/pack-1.pub"), include_str!("../../../keys/pack-2.pub")];

pub fn trusted_keys() -> Vec<VerifyingKey> {
    TRUSTED_PACK_KEYS.iter().filter_map(|k| verifying_key_from_hex(k).ok()).collect()
}

pub fn verifying_key_from_hex(s: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(s.trim())
        .context("public key is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key is not 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

/// The highest pack version this install has accepted, kept in the data directory so a client
/// never goes back to an older pack (rollback protection, ADR 0002). An equal version is taken
/// again only when it is byte-for-byte the same pack.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackState {
    pub version: u64,
    pub sha256: String,
}

impl PackState {
    /// Reads the state file. A missing file means nothing accepted yet; a damaged one is an error
    /// (silently starting from zero would reopen the rollback hole).
    pub fn load(path: &std::path::Path) -> Result<PackState> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("{} is damaged", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PackState::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Refuses `pack` if it is older than the accepted one, or the same version with other bytes.
    pub fn check(&self, pack: &Pack, json: &[u8]) -> Result<()> {
        let digest = hex::encode(Sha256::digest(json));
        if pack.version < self.version {
            bail!("rule pack version {} is older than the accepted version {}; refusing (rollback)", pack.version, self.version);
        }
        if pack.version == self.version && !self.sha256.is_empty() && !digest.eq_ignore_ascii_case(&self.sha256) {
            bail!("rule pack version {} differs from the accepted pack with the same version; refusing", pack.version);
        }
        Ok(())
    }

    /// Checks `pack` and, when it passes, records it as the highest accepted (written to a
    /// temporary file and renamed, so a crash leaves the old state intact).
    pub fn accept(path: &std::path::Path, pack: &Pack, json: &[u8]) -> Result<PackState> {
        let current = PackState::load(path)?;
        current.check(pack, json)?;
        let next = PackState { version: pack.version, sha256: hex::encode(Sha256::digest(json)) };
        if next != current {
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec(&next)?).with_context(|| format!("writing {}", tmp.display()))?;
            std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(json: &str) -> (Vec<u8>, String, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let sig = hex::encode(sk.sign(json.as_bytes()).to_bytes());
        (json.as_bytes().to_vec(), sig, sk.verifying_key())
    }

    #[test]
    fn rfc3339_and_unix_seconds() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-11-26T06:00:00Z"), Some(1_795_672_800));
        assert_eq!(parse_rfc3339("2026-11-26T13:00:00.123+07:00"), Some(1_795_672_800));
        assert_eq!(parse_rfc3339("2000-02-29T00:00:00Z"), Some(951_782_400));
        for bad in ["2026-11-26", "2026-13-01T00:00:00Z", "2026-11-26T06:00:00", "2026-11-26T06:00:00+0700"] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
        let a = Pack::parse(br#"{"format":1,"version":1,"published":"x","expires":"2026-11-26T06:00:00Z"}"#).unwrap();
        let b = Pack::parse(br#"{"format":1,"version":1,"published":"x","expires":1795672800}"#).unwrap();
        assert_eq!(a.expires, b.expires);
        assert!(Pack::parse(br#"{"format":1,"version":1,"published":"x","expires":"tomorrow"}"#).is_err());
    }

    #[test]
    fn verified_packs_need_an_unexpired_expiry_but_dev_packs_do_not() {
        let now = 1_000_000;
        assert!(Pack::parse(br#"{"format":1,"version":1,"published":"x"}"#).is_ok(), "unsigned dev pack without expires");
        let (j, s, k) = signed(r#"{"format":1,"version":1,"published":"x"}"#);
        assert!(Pack::verified_at(&j, &s, &[k], now).is_err(), "no expires");
        assert!(Pack::signature_checked(&j, &s, &[k]).is_ok());
        let (j, s, k) = signed(r#"{"format":1,"version":1,"published":"x","expires":1000000}"#);
        assert!(Pack::verified_at(&j, &s, &[k], now).is_err(), "expired");
        let (j, s, k) = signed(r#"{"format":1,"version":1,"published":"x","expires":1000001}"#);
        assert!(Pack::verified_at(&j, &s, &[k], now).is_ok());
        let mut later = j.clone();
        let at = later.len() - 3;
        later[at] = b'9'; // a later expiry, without re-signing
        assert!(Pack::verified_at(&later, &s, &[k], now).is_err(), "expires is covered by the signature");
    }

    #[test]
    fn hash_sets_default_to_suspicious_and_untrusted() {
        let p = Pack::parse(br#"{"format":1,"version":1,"published":"x","hash_sets":[{"file":"a.bin","sha256":"00","family":"f","source":"s"}]}"#).unwrap();
        assert_eq!(p.hash_sets[0].severity, Severity::Suspicious);
        assert!(!p.hash_sets[0].trusted);
    }

    #[test]
    fn pack_state_refuses_rollback_and_same_version_with_other_bytes() {
        let dir = std::env::temp_dir().join(format!("genra-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pack-state.json");
        let pack = |v: u64, extra: &str| {
            let j = format!(r#"{{"format":1,"version":{v},"published":"{extra}"}}"#);
            (Pack::parse(j.as_bytes()).unwrap(), j.into_bytes())
        };
        let (p5, j5) = pack(5, "a");
        assert_eq!(PackState::accept(&path, &p5, &j5).unwrap().version, 5);
        assert!(PackState::accept(&path, &p5, &j5).is_ok(), "same bytes again");
        let (p5b, j5b) = pack(5, "b");
        assert!(PackState::accept(&path, &p5b, &j5b).is_err(), "same version, other bytes");
        let (p4, j4) = pack(4, "a");
        assert!(PackState::accept(&path, &p4, &j4).is_err(), "older");
        let (p6, j6) = pack(6, "a");
        assert!(PackState::accept(&path, &p6, &j6).is_ok());
        assert_eq!(PackState::load(&path).unwrap().version, 6, "persisted");
        std::fs::write(&path, b"garbage").unwrap();
        assert!(PackState::load(&path).is_err(), "damaged state is an error, not a reset");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn english_messages_are_optional_and_every_base_rule_has_one() {
        let old = Pack::parse(br#"{"format":1,"version":1,"published":"x","rules":[{"id":"r","family":"F","severity":"malware","message_vi":"m"}]}"#).unwrap();
        assert_eq!(old.rules[0].message_en, None, "a pack written before message_en still loads");
        let json = serde_json::to_string(&old).unwrap();
        assert!(!json.contains("message_en"), "and is written back without it");
        let base = Pack::parse(include_bytes!("../../../rules/base.json")).unwrap();
        assert!(!base.rules.is_empty());
        for r in &base.rules {
            assert!(r.message_en.as_deref().is_some_and(|m| !m.trim().is_empty()), "{} has no message_en", r.id);
        }
    }

    #[test]
    fn both_official_keys_parse() {
        assert_eq!(super::trusted_keys().len(), 2);
    }
}
