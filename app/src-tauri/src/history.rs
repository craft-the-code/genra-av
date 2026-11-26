//! "Lịch sử & hoàn tác": what Genra checked, moved aside or repaired, newest first, with the undo
//! that goes with each. Kept in `<data_dir>/history.json`.

use anyhow::Result;
use genra_av_core::rules::Severity;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KEEP: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Check,
    QuickScan,
    Quarantine,
    /// "Dọn sạch giúp tôi": the file, Excel's startup folder and other infected files.
    Repair,
    /// "Sửa giúp tôi" on a health item; `family` holds the fix id.
    Fix,
    /// "Tắt" on a startup item; `name` is the item.
    StartupOff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Undo {
    /// Put a quarantined file back (`quarantine::Quarantine::restore`).
    Quarantine { id: String },
    /// Undo a whole journal group (a repair, a fix, a startup item switched off).
    Group { id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    /// Unix seconds.
    pub at: i64,
    pub kind: Kind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Severity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Quick scan: files looked at, and how many needed action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hits: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo: Option<Undo>,
    #[serde(default)]
    pub undone: bool,
}

pub struct History {
    path: PathBuf,
    pub entries: Vec<Entry>,
}

impl History {
    pub fn load(data: &Path) -> History {
        let path = data.join("history.json");
        let entries = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        History { path, entries }
    }

    pub fn push(&mut self, e: Entry) -> Result<()> {
        self.entries.insert(0, e);
        self.entries.truncate(KEEP);
        self.save()
    }

    pub fn mark_undone(&mut self, undo: &Undo) -> Result<()> {
        for e in self.entries.iter_mut().filter(|e| e.undo.as_ref() == Some(undo)) {
            e.undone = true;
        }
        self.save()
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::util::write_atomic(&self.path, &serde_json::to_vec_pretty(&self.entries)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_newest_first_and_marks_undone() {
        let dir = std::env::temp_dir().join(format!("genra-app-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut h = History::load(&dir);
        let entry = |id: &str, undo: Option<Undo>| Entry {
            id: id.into(),
            at: 1,
            kind: Kind::Quarantine,
            name: id.into(),
            path: None,
            verdict: None,
            family: None,
            files: None,
            hits: None,
            undo,
            undone: false,
        };
        h.push(entry("a", None)).unwrap();
        h.push(entry("b", Some(Undo::Quarantine { id: "q1".into() }))).unwrap();
        h.mark_undone(&Undo::Quarantine { id: "q1".into() }).unwrap();
        let again = History::load(&dir);
        assert_eq!(again.entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), ["b", "a"]);
        assert!(again.entries[0].undone);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
