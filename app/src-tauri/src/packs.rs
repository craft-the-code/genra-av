//! Rule pack updates (ADR 0002). On start and every 6 hours the app downloads the signed pack
//! from the rolling `rules-latest` release, checks the signature, the expiry, the version against
//! the highest one this install accepted, and the hash lists against the digests the pack names,
//! then swaps it into `<data_dir>/packs/current/`. Any failure keeps what is installed; with
//! nothing installed the app uses the pack compiled into it.

use anyhow::{bail, Context, Result};
use ed25519_dalek::VerifyingKey;
use genra_av_core::reputation::Reputation;
use genra_av_core::rules::{trusted_keys, unix_now, Pack, PackState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const RELEASE_BASE: &str = "https://github.com/craft-the-code/genra-av/releases/download/rules-latest/";
pub const MAX_PACK: u64 = 1024 * 1024;
pub const MAX_SIG: u64 = 4 * 1024;
pub const MAX_LIST: u64 = 64 * 1024 * 1024;
pub const UPDATE_EVERY: Duration = Duration::from_secs(6 * 3600);

/// The pack that ships inside the app, used only while no signed pack is installed (a fresh
/// install that has not reached GitHub yet, or every installed pack failing its checks).
///
/// It is parsed without a signature on purpose. `rules/base.json` is compiled into the binary,
/// so it is exactly as trustworthy as the binary itself: anyone able to swap these bytes could
/// swap the code that checks a signature too. The binary's own signature is what protects it
/// (macOS: Developer ID + notarisation; Windows: unsigned during the beta, SignPath planned for
/// v1.0, docs/release-plan.md). Signing it would need the pack key in the app build, which the release job
/// does not hold (only the `rule-pack` job does, ADR 0002). Downloaded packs are different:
/// they arrive over the network, so [`load_installed`] verifies their signature, expiry,
/// version and hash lists on every load, and an installed pack always wins over this one.
static BUNDLED: &[u8] = include_bytes!("../../../rules/base.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Bundled,
    Installed,
}

pub struct Loaded {
    pub pack: Pack,
    pub reputation: Reputation,
    pub source: Source,
}

/// What the last update attempts did, kept in `packs/status.json` so the window can say when the
/// rules were last confirmed current.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Status {
    /// Unix seconds of the last check that ended with the newest pack installed.
    pub last_ok: Option<i64>,
    pub last_try: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Installed(u64),
    UpToDate(u64),
}

pub fn packs_dir(data: &Path) -> PathBuf {
    data.join("packs")
}

fn state_path(data: &Path) -> PathBuf {
    data.join("pack-state.json")
}

pub fn bundled() -> Loaded {
    let pack = Pack::parse(BUNDLED).expect("bundled rules/base.json is valid");
    Loaded { pack, reputation: Reputation::default(), source: Source::Bundled }
}

/// The installed pack, verified again on every load (signature, expiry, not older than the
/// accepted version, hash lists matching). `previous` covers a crash in the middle of a swap.
pub fn load_installed(data: &Path, keys: &[VerifyingKey], now: i64) -> Result<Loaded> {
    let dir = packs_dir(data);
    let mut last = anyhow::anyhow!("no rule pack installed");
    for name in ["current", "previous"] {
        match load_dir(data, &dir.join(name), keys, now) {
            Ok(l) => return Ok(l),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn load_dir(data: &Path, dir: &Path, keys: &[VerifyingKey], now: i64) -> Result<Loaded> {
    let json = std::fs::read(dir.join("pack.json")).with_context(|| format!("reading {}", dir.display()))?;
    let sig = std::fs::read_to_string(dir.join("pack.json.sig"))?;
    let pack = Pack::verified_at(&json, &sig, keys, now)?;
    PackState::load(&state_path(data))?.check(&pack, &json)?;
    let reputation = Reputation::load(&pack, dir)?;
    Ok(Loaded { pack, reputation, source: Source::Installed })
}

pub fn load(data: &Path) -> Loaded {
    load_installed(data, &trusted_keys(), unix_now()).unwrap_or_else(|_| bundled())
}

pub fn read_status(data: &Path) -> Status {
    std::fs::read(packs_dir(data).join("status.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn write_status(data: &Path, s: &Status) -> Result<()> {
    let dir = packs_dir(data);
    std::fs::create_dir_all(&dir)?;
    crate::util::write_atomic(&dir.join("status.json"), &serde_json::to_vec_pretty(s)?)
}

/// Where the files come from; the real one is [`Http`], tests use a folder.
pub trait Fetch {
    fn get(&self, file: &str, cap: u64) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

pub struct Http {
    client: reqwest::Client,
    base: String,
}

impl Http {
    pub fn new() -> Result<Http> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .user_agent(concat!("genra-av-app/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Http { client, base: RELEASE_BASE.to_string() })
    }
}

impl Fetch for Http {
    async fn get(&self, file: &str, cap: u64) -> Result<Vec<u8>> {
        // Small files get a short deadline; a 64 MB list on a slow office line gets longer.
        let timeout = if cap > MAX_PACK { Duration::from_secs(600) } else { Duration::from_secs(30) };
        let mut res = self.client.get(format!("{}{file}", self.base)).timeout(timeout).send().await.with_context(|| format!("downloading {file}"))?;
        if !res.status().is_success() {
            bail!("downloading {file}: HTTP {}", res.status());
        }
        if res.content_length().is_some_and(|n| n > cap) {
            bail!("{file} is larger than {cap} bytes");
        }
        let mut out = Vec::new();
        while let Some(chunk) = res.chunk().await.with_context(|| format!("downloading {file}"))? {
            if out.len() as u64 + chunk.len() as u64 > cap {
                bail!("{file} is larger than {cap} bytes");
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// A hash list name is used in a URL and a path: plain names only.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('.') && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Downloads, checks and installs the newest pack. On any error nothing installed changes.
pub async fn update<F: Fetch>(data: &Path, fetch: &F, keys: &[VerifyingKey], now: i64) -> Result<Outcome> {
    let json = fetch.get("pack.json", MAX_PACK).await?;
    let sig = String::from_utf8(fetch.get("pack.json.sig", MAX_SIG).await?).context("signature is not text")?;
    let pack = Pack::verified_at(&json, &sig, keys, now)?;
    let dir = packs_dir(data);
    let current = dir.join("current");
    if let Ok(installed) = std::fs::read(current.join("pack.json")) {
        if Sha256::digest(&installed) == Sha256::digest(&json) && load_dir(data, &current, keys, now).is_ok() {
            return Ok(Outcome::UpToDate(pack.version));
        }
        if let Ok(old) = Pack::parse(&installed) {
            if pack.version <= old.version && load_dir(data, &current, keys, now).is_ok() {
                bail!("rule pack version {} is not newer than the installed {}", pack.version, old.version);
            }
        }
    }
    PackState::load(&state_path(data))?.check(&pack, &json)?;

    std::fs::create_dir_all(&dir)?;
    let staging = dir.join(format!("staging-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&staging)?;
    let staged = async {
        for set in &pack.hash_sets {
            if !plain_name(&set.file) {
                bail!("hash list name {:?} is not a plain file name", set.file);
            }
            let bytes = fetch.get(&set.file, MAX_LIST).await?;
            std::fs::write(staging.join(&set.file), bytes)?;
        }
        // Checks every list's SHA-256 and count against the signed pack.
        Reputation::load(&pack, &staging)?;
        std::fs::write(staging.join("pack.json"), &json)?;
        std::fs::write(staging.join("pack.json.sig"), sig.as_bytes())?;
        install(&dir, &staging)?;
        Ok(())
    }
    .await;
    if let Err(e) = staged {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    // Recorded after the swap: a failed swap must not raise the floor above what is installed.
    PackState::accept(&state_path(data), &pack, &json)?;
    Ok(Outcome::Installed(pack.version))
}

/// `staging` becomes `current`; the old `current` stays as `previous` until the swap is done.
fn install(dir: &Path, staging: &Path) -> Result<()> {
    let current = dir.join("current");
    let previous = dir.join("previous");
    let _ = std::fs::remove_dir_all(&previous);
    if current.exists() {
        std::fs::rename(&current, &previous).context("moving the old pack aside")?;
    }
    if let Err(e) = std::fs::rename(staging, &current) {
        if previous.exists() {
            let _ = std::fs::rename(&previous, &current);
        }
        return Err(anyhow::Error::new(e).context("installing the new pack"));
    }
    let _ = std::fs::remove_dir_all(&previous);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use genra_av_core::reputation::HashList;
    use std::collections::HashMap;

    struct Mem(HashMap<String, Vec<u8>>);
    impl Fetch for Mem {
        async fn get(&self, file: &str, cap: u64) -> Result<Vec<u8>> {
            let b = self.0.get(file).cloned().with_context(|| format!("404 {file}"))?;
            if b.len() as u64 > cap {
                bail!("too large");
            }
            Ok(b)
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn release(version: u64, list: &[u8], count: usize) -> Mem {
        let digest = hex::encode(Sha256::digest(list));
        let json = format!(
            r#"{{"format":1,"version":{version},"published":"t","expires":4000000000,"hash_sets":[{{"file":"l{version}.bin","sha256":"{digest}","family":"f","source":"s","count":{count}}}]}}"#
        );
        let sig = hex::encode(key().sign(json.as_bytes()).to_bytes());
        Mem(HashMap::from([
            ("pack.json".into(), json.into_bytes()),
            ("pack.json.sig".into(), sig.into_bytes()),
            (format!("l{version}.bin"), list.to_vec()),
        ]))
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("genra-app-packs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn block<T>(f: impl std::future::Future<Output = T>) -> T {
        tauri::async_runtime::block_on(f)
    }

    #[test]
    fn installs_refuses_older_and_keeps_previous_on_failure() {
        let data = tmp("install");
        let keys = [key().verifying_key()];
        let list = HashList::build_from_text(&format!("{}\n", "ab".repeat(32))).unwrap();
        assert_eq!(block(update(&data, &release(5, &list, 1), &keys, 1)).unwrap(), Outcome::Installed(5));
        assert_eq!(load_installed(&data, &keys, 1).unwrap().reputation.entries(), 1);
        assert_eq!(block(update(&data, &release(5, &list, 1), &keys, 1)).unwrap(), Outcome::UpToDate(5));
        assert!(block(update(&data, &release(4, &list, 1), &keys, 1)).is_err(), "older version refused");

        // A list whose count does not match: refused, version 5 stays installed.
        assert!(block(update(&data, &release(6, &list, 2), &keys, 1)).is_err());
        assert_eq!(load_installed(&data, &keys, 1).unwrap().pack.version, 5);
        // A list with the wrong bytes (digest mismatch).
        let mut bad = release(7, &list, 1);
        bad.0.insert("l7.bin".into(), vec![1u8; 32]);
        assert!(block(update(&data, &bad, &keys, 1)).is_err());
        // Wrong signing key.
        let other = [SigningKey::from_bytes(&[1u8; 32]).verifying_key()];
        assert!(block(update(&data, &release(8, &list, 1), &other, 1)).is_err());
        assert_eq!(load_installed(&data, &keys, 1).unwrap().pack.version, 5);
        assert!(std::fs::read_dir(packs_dir(&data)).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with("staging")));

        assert_eq!(block(update(&data, &release(9, &list, 1), &keys, 1)).unwrap(), Outcome::Installed(9));
        // Expired: the installed pack is refused on load and the app falls back.
        assert!(load_installed(&data, &keys, 4_000_000_000).is_err());
        let _ = std::fs::remove_dir_all(&data);
    }

    #[test]
    fn oversized_and_odd_names_are_refused() {
        assert!(plain_name("malwarebazaar-2026112611.bin"));
        for bad in ["", ".hidden", "../x.bin", "a/b.bin", "a b.bin"] {
            assert!(!plain_name(bad), "{bad}");
        }
        let data = tmp("big");
        let mut r = release(3, &[], 0);
        r.0.insert("pack.json".into(), vec![b' '; MAX_PACK as usize + 1]);
        assert!(block(update(&data, &r, &[key().verifying_key()], 1)).is_err());
        let _ = std::fs::remove_dir_all(&data);
    }

    #[test]
    fn bundled_pack_parses() {
        assert_eq!(bundled().source, Source::Bundled);
    }
}
