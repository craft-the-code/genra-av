//! Paths the window may act on. The web view never names an arbitrary path: a command that takes
//! one accepts it only if, in this session, the user picked it in the open dialog, dropped it on
//! the window, passed it on the command line, or a scan or repair produced it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct Allow(HashSet<PathBuf>);

impl Allow {
    pub fn add(&mut self, p: &Path) {
        self.0.insert(p.to_path_buf());
    }

    pub fn check(&self, p: &str) -> Result<PathBuf, String> {
        let path = PathBuf::from(p);
        if self.0.contains(&path) {
            Ok(path)
        } else {
            Err("not_allowed".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_paths_pass() {
        let mut a = Allow::default();
        a.add(Path::new("/tmp/a.xls"));
        assert!(a.check("/tmp/a.xls").is_ok());
        assert_eq!(a.check("/tmp/b.xls").unwrap_err(), "not_allowed");
        assert!(a.check("/tmp/../tmp/a.xls").is_err(), "no normalising into an allowed path");
    }
}
