//! Genra AV machine repair: what the desktop app calls to clean the machine, not just the file.
//!
//! - [`journal`]: every change is written down before it is made, with what is needed to undo it;
//!   a repair is one group, undone with one press.
//! - [`repair`]: the fixed list of repair actions, the "Dọn sạch giúp tôi" plan for a detected
//!   file, and the runner that stops cleanly and rolls back when a step fails.
//! - [`office`]: is Excel running, which workbooks are open, and asking it (politely) to close.
//! - [`health`]: Defender / Gatekeeper, updates, firewall and the Office macro setting.
//! - [`startup`]: what starts with the machine, and which of those look wrong.
//!
//! Rules kept everywhere: documents are only parsed, never opened in an app; every helper
//! process runs with a timeout and no window; nothing goes on the network; nothing asks for
//! admin rights; user data is never deleted (it goes through quarantine and the journal).

pub mod attrs;
pub mod health;
pub mod journal;
pub mod office;
mod proc;
pub mod rails;
pub mod reg;
pub mod repair;
pub mod startup;
pub mod traces;
pub mod usb;

pub use journal::Journal;

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
pub(crate) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `bytes` random bytes as hex.
pub(crate) fn random_hex(bytes: usize) -> anyhow::Result<String> {
    let mut b = vec![0u8; bytes];
    getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("no system randomness: {e}"))?;
    Ok(hex::encode(b))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// The user's home folder, absolute only.
pub(crate) fn home() -> Option<std::path::PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
}
