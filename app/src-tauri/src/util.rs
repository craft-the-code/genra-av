//! Small helpers shared by the app modules.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

/// Writes `bytes` to a temporary file beside `path`, flushes it, and renames it over `path`, so a
/// crash leaves either the old or the new content, never half of it.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4().simple()));
    let mut f = std::fs::File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display())).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

pub fn now() -> i64 {
    genra_av_core::rules::unix_now()
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

pub fn file_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string())
}
