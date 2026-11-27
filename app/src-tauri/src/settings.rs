//! Settings that change what leaves the machine live on the Rust side (`<data_dir>/settings.json`),
//! so the window cannot turn sending on by itself. Theme and language stay in the window.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Q8: when a file is found to be malware or suspicious, send its SHA-256 and the rule id
    /// (never the file) so families can be counted. Off until the user turns it on.
    #[serde(default)]
    pub send_hashes: bool,
    /// Windows: "Kiểm tra bằng Genra AV" in the Explorer right-click menu. On unless switched off.
    #[serde(default = "yes")]
    pub shell_menu: bool,
    /// "Canh gác": watch Downloads, Zalo and USB sticks while Genra runs. On unless switched off.
    #[serde(default = "yes")]
    pub guard: bool,
}

fn yes() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { send_hashes: false, shell_menu: true, guard: true }
    }
}

impl Settings {
    pub fn load(data: &Path) -> Settings {
        std::fs::read(data.join("settings.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&self, data: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(data)?;
        crate::util::write_atomic(&data.join("settings.json"), &serde_json::to_vec_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_settings_files_keep_the_menu_on() {
        let s: Settings = serde_json::from_str(r#"{"send_hashes":true}"#).unwrap();
        assert!(s.send_hashes && s.shell_menu && s.guard);
        assert!(Settings::default().shell_menu && !Settings::default().send_hashes);
    }
}
