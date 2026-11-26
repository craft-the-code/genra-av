//! Where Genra keeps its cache, quarantine, pack state and installed rule packs. The command line
//! and the desktop app share this one folder, so a pack or a quarantined file is seen by both.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::PathBuf;

/// `GENRA_AV_DATA_DIR` (absolute) overrides the platform folder, for tests and portable setups.
pub const DATA_DIR_ENV: &str = "GENRA_AV_DATA_DIR";

/// The data folder: `%LOCALAPPDATA%\Genra AV` on Windows, `~/Library/Application Support/Genra AV`
/// on macOS, `$XDG_DATA_HOME/genra-av` (or `~/.local/share/genra-av`) elsewhere.
pub fn data_dir() -> Result<PathBuf> {
    data_dir_from(|k| std::env::var_os(k))
}

/// [`data_dir`] with the environment passed in. Only absolute paths are taken: with no home
/// folder this fails instead of quietly using the current directory.
pub fn data_dir_from(env: impl Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    let abs = |k: &str| env(k).map(PathBuf::from).filter(|p| p.is_absolute());
    if let Some(p) = abs(DATA_DIR_ENV) {
        return Ok(p);
    }
    let home = || {
        abs(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .context("no home folder (HOME/USERPROFILE unset or not absolute); cannot find the data folder")
    };
    Ok(if cfg!(windows) {
        match abs("LOCALAPPDATA") {
            Some(p) => p,
            None => home()?.join("AppData").join("Local"),
        }
        .join("Genra AV")
    } else if cfg!(target_os = "macos") {
        home()?.join("Library/Application Support/Genra AV")
    } else {
        match abs("XDG_DATA_HOME") {
            Some(p) => p,
            None => home()?.join(".local/share"),
        }
        .join("genra-av")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_needs_an_absolute_home() {
        assert!(data_dir_from(|_| None).is_err(), "no HOME/USERPROFILE: error, not the cwd");
        assert!(data_dir_from(|_| Some(OsString::from("relative"))).is_err());
        let home = if cfg!(windows) { "C:\\Users\\a" } else { "/home/a" };
        let d = data_dir_from(|k| (k == "HOME" || k == "USERPROFILE").then(|| OsString::from(home))).unwrap();
        assert!(d.is_absolute() && d.starts_with(home), "{}", d.display());
    }

    #[test]
    fn override_must_be_absolute() {
        let over = if cfg!(windows) { "C:\\genra-test" } else { "/tmp/genra-test" };
        let home = if cfg!(windows) { "C:\\Users\\a" } else { "/home/a" };
        let env = |v: &'static str| {
            move |k: &str| match k {
                DATA_DIR_ENV => Some(OsString::from(v)),
                "HOME" | "USERPROFILE" => Some(OsString::from(home)),
                _ => None,
            }
        };
        assert_eq!(data_dir_from(env(over)).unwrap(), PathBuf::from(over));
        assert!(data_dir_from(env("relative")).unwrap().starts_with(home), "a relative override is ignored");
    }
}
