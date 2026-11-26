//! Rule packs: detection logic shipped as data, so a new threat is caught by publishing a pack,
//! not by releasing the app. A pack is JSON plus a detached Ed25519 signature; the app only
//! loads packs signed by a key it was built with (docs/adr/0002-signed-rule-packs.md).

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const PACK_FORMAT: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pack {
    pub format: u32,
    /// Monotonic: a client refuses a pack older than the one it has (rollback protection).
    pub version: u64,
    pub published: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Files we know are fine though a rule matches them: the false-positive kill switch.
    #[serde(default)]
    pub allow_sha256: Vec<String>,
    /// Rule ids switched off without shipping a new rule set.
    #[serde(default)]
    pub disabled: Vec<String>,
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
    #[serde(default)]
    pub when: When,
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

    /// Parses only after the signature over the exact bytes checks out against one of `keys`.
    pub fn verified(json: &[u8], sig_hex: &str, keys: &[VerifyingKey]) -> Result<Pack> {
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

pub fn verifying_key_from_hex(s: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(s.trim())
        .context("public key is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key is not 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}
