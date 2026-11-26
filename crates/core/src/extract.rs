//! Turns a file's bytes into the facts rules match on: what kind of container it is, and the
//! VBA modules inside it (name + source). OLE2 (.xls/.doc/.ppt and vbaProject.bin) and OOXML
//! zips (.xlsm/.docm/.pptm, also a renamed .xlsx carrying vbaProject.bin) are understood.

use crate::ovba;
use anyhow::Result;
use std::io::{Cursor, Read};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Ole,
    Zip,
    Other,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VbaModule {
    pub name: String,
    #[serde(skip)]
    pub source: String,
    pub bytes: usize,
}

#[derive(Debug, Default)]
pub struct Facts {
    pub vba: Vec<VbaModule>,
    /// A VBA project was present but could not be read: treat as suspicious, never as clean.
    pub vba_unreadable: bool,
}

const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
/// Cap on a single zip member read, so a zip bomb cannot exhaust memory.
const MEMBER_CAP: u64 = 64 * 1024 * 1024;

pub fn kind(bytes: &[u8]) -> Kind {
    if bytes.starts_with(&OLE_MAGIC) {
        Kind::Ole
    } else if bytes.starts_with(b"PK\x03\x04") {
        Kind::Zip
    } else {
        Kind::Other
    }
}

pub fn facts(bytes: &[u8]) -> Facts {
    let mut f = Facts::default();
    match kind(bytes) {
        Kind::Ole => ole_vba(bytes, &mut f),
        Kind::Zip => {
            if zip_vba(bytes, &mut f).is_err() {
                // A broken zip is not our verdict to give; the facts stay empty.
            }
        }
        Kind::Other => {}
    }
    f
}

fn zip_vba(bytes: &[u8], f: &mut Facts) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    for i in 0..archive.len() {
        let member = archive.by_index(i)?;
        if !member.name().to_ascii_lowercase().ends_with("vbaproject.bin") {
            continue;
        }
        let mut inner = Vec::new();
        member.take(MEMBER_CAP).read_to_end(&mut inner)?;
        ole_vba(&inner, f);
    }
    Ok(())
}

fn ole_vba(bytes: &[u8], f: &mut Facts) {
    let Ok(mut comp) = cfb::CompoundFile::open(Cursor::new(bytes)) else {
        return;
    };
    let dirs: Vec<PathBuf> = comp
        .walk()
        .filter(|e| e.is_stream() && e.name().eq_ignore_ascii_case("dir"))
        .map(|e| e.path().to_path_buf())
        .collect();
    for dir_path in dirs {
        let Some(vba_storage) = dir_path.parent().map(|p| p.to_path_buf()) else { continue };
        let Ok(dir_raw) = read_stream(&mut comp, &dir_path) else {
            f.vba_unreadable = true;
            continue;
        };
        let Ok(dir) = ovba::decompress(&dir_raw) else {
            f.vba_unreadable = true;
            continue;
        };
        let mods = ovba::modules(&dir);
        if mods.is_empty() {
            f.vba_unreadable = true;
        }
        for m in mods {
            let stream = vba_storage.join(&m.stream_name);
            let source = read_stream(&mut comp, &stream)
                .ok()
                .and_then(|raw| raw.get(m.text_offset as usize..).map(|s| s.to_vec()))
                .and_then(|s| ovba::decompress(&s).ok());
            match source {
                Some(src) => f.vba.push(VbaModule { name: m.name, bytes: src.len(), source: ovba::latin1(&src) }),
                None => f.vba_unreadable = true,
            }
        }
    }
}

fn read_stream(comp: &mut cfb::CompoundFile<Cursor<&[u8]>>, path: &std::path::Path) -> Result<Vec<u8>> {
    let mut s = comp.open_stream(path)?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    Ok(buf)
}
