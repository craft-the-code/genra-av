//! Turns a file's bytes into the facts rules match on: what kind of container it is, and the
//! VBA modules inside it (name + source). OLE2 (.xls/.doc/.ppt and vbaProject.bin) and OOXML
//! zips (.xlsm/.docm/.pptm, also a renamed .xlsx carrying vbaProject.bin) are understood.
//!
//! A VBA project is looked for in every zip member that is an OLE2 file (whatever its name), in
//! every member whose content type says vbaProject, and inside embedded zips and OLE streams that
//! are themselves containers (a few levels deep). Anything that cannot be read to the end (a broken
//! zip, a member over the decompression budget, a claimed VBA part that is not OLE2) sets
//! [`Facts::vba_unreadable`]: suspicious, never clean.

pub(crate) mod opc;

use crate::ovba;
use anyhow::{bail, ensure, Context, Result};
use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

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
    /// A VBA project was (or may have been) present but could not be read: treat as suspicious,
    /// never as clean.
    pub vba_unreadable: bool,
    /// Excel 4.0 (XLM) macros: macro sheets, and names Excel runs on open/close (Auto_Open…).
    /// Old, but still used by droppers because many scanners only look at VBA.
    pub xlm: Vec<String>,
    /// A BIFF8 workbook whose sheet list is encrypted, so Excel 4.0 macros cannot be checked.
    /// Office files protected with a password look the same; reported for information only.
    pub workbook_encrypted: bool,
    /// Templates a document loads from outside itself when opened (remote template injection):
    /// the target, an http(s), UNC or file address.
    pub remote_templates: Vec<String>,
}

pub(crate) const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
pub(crate) const ZIP_MAGIC: &[u8; 4] = b"PK\x03\x04";
/// Total bytes decompressed or copied out of one input file, across all its members and nested
/// containers. A zip bomb runs into this and is reported, never silently truncated.
pub const ZIP_BUDGET: u64 = 256 * 1024 * 1024;
/// Most zip entries one package may have (Office files have tens to a few thousand).
pub const MAX_ZIP_ENTRIES: usize = 20_000;
/// Cap on one XML part ([Content_Types].xml, a .rels part, ...).
pub(crate) const XML_CAP: u64 = 64 * 1024 * 1024;
/// Cap on one relationship part or workbook.xml read for the XLM / remote-template checks, and the
/// total for those reads per package: real ones are a few KB.
const META_PART_CAP: u64 = 1024 * 1024;
const META_BUDGET: u64 = 8 * 1024 * 1024;
/// Most of a Workbook stream read to look for Excel 4.0 macros; kept apart from the shared budget.
const WORKBOOK_CAP: u64 = 64 * 1024 * 1024;
/// Containers inside containers (docx → oleObject.bin → Package stream → xlsm ...).
const MAX_NESTING: usize = 4;
const CONTENT_TYPES: &str = "[content_types].xml";

pub fn kind(bytes: &[u8]) -> Kind {
    if bytes.starts_with(&OLE_MAGIC) {
        Kind::Ole
    } else if bytes.starts_with(ZIP_MAGIC) {
        Kind::Zip
    } else {
        Kind::Other
    }
}

pub fn facts(bytes: &[u8]) -> Facts {
    let mut f = Facts::default();
    let mut budget = Budget::new(ZIP_BUDGET);
    match kind(bytes) {
        Kind::Ole => ole_vba(bytes, &mut f, &mut budget, 0),
        Kind::Zip => {
            if zip_vba(bytes, &mut f, &mut budget, 0).is_err() {
                // A zip we cannot read to the end might hold anything: never call it clean.
                f.vba_unreadable = true;
            }
        }
        Kind::Other => {}
    }
    f
}

// ---- plain zip archives (for the archive check in lib.rs) ----

/// One entry of a plain zip: its name, whether it is encrypted, and its bytes when it could be
/// read within the budget.
pub struct ZipEntry {
    pub name: String,
    pub encrypted: bool,
    pub data: Option<Vec<u8>>,
}

/// An OOXML package (it has `[Content_Types].xml`): read by the Office checks, not as an archive.
pub fn is_office_package(bytes: &[u8]) -> bool {
    open_zip(bytes).map(|ar| content_types_index(&ar).is_some()).unwrap_or(false)
}

/// Entries of a plain zip, at most `max` of them, files only, read on the same budget as Office
/// packages (a zip bomb costs a bounded amount and the rest is skipped).
pub fn zip_entries(bytes: &[u8], max: usize) -> Result<Vec<ZipEntry>> {
    let mut ar = open_zip(bytes)?;
    let mut budget = Budget::new(ZIP_BUDGET);
    let mut out = Vec::new();
    for i in 0..ar.len().min(max) {
        let (name, encrypted, is_dir) = {
            let f = ar.by_index_raw(i)?;
            (f.name().to_string(), f.encrypted(), f.is_dir())
        };
        if is_dir {
            continue;
        }
        let data = if encrypted { None } else { budget.read(&mut ar, i, 64 * 1024 * 1024).ok() };
        out.push(ZipEntry { name: name.rsplit('/').next().unwrap_or(&name).to_string(), encrypted, data });
    }
    Ok(out)
}

// ---- zip reading shared with the cleaner ----

/// Decompression budget for one input file.
pub(crate) struct Budget {
    left: u64,
}

impl Budget {
    pub fn new(total: u64) -> Self {
        Budget { left: total }
    }

    /// Whole member `i`, at most `cap` bytes; over the cap or the budget is an error.
    pub fn read(&mut self, ar: &mut ZipArchive<Cursor<&[u8]>>, i: usize, cap: u64) -> Result<Vec<u8>> {
        let f = ar.by_index(i)?;
        let name = f.name().to_string();
        let limit = cap.min(self.left);
        ensure!(f.size() <= limit, "{name}: {} bytes is over the {limit}-byte budget", f.size());
        let mut buf = Vec::with_capacity(f.size() as usize);
        let read = f.take(limit + 1).read_to_end(&mut buf);
        // Charged whether or not the read succeeds: a member that lies about its size and fails
        // part way must still cost what it made us decompress, or a package of many such members
        // keeps the scanner busy for free.
        self.left = self.left.saturating_sub(buf.len() as u64);
        read.with_context(|| format!("reading {name}"))?;
        ensure!(buf.len() as u64 <= limit, "{name}: decompresses past the {limit}-byte budget");
        Ok(buf)
    }

    /// First bytes of member `i` (to sniff OLE2 / zip magic) without decompressing the rest.
    pub fn head(&mut self, ar: &mut ZipArchive<Cursor<&[u8]>>, i: usize) -> Result<Vec<u8>> {
        let f = ar.by_index(i)?;
        let mut buf = Vec::with_capacity(8);
        f.take(8).read_to_end(&mut buf)?;
        self.left = self.left.saturating_sub(buf.len() as u64);
        Ok(buf)
    }

    /// Charges bytes read outside a zip (an OLE stream) to the same budget.
    fn charge(&mut self, n: u64) -> Result<()> {
        ensure!(n <= self.left, "over the {ZIP_BUDGET}-byte read budget");
        self.left -= n;
        Ok(())
    }

    fn left(&self) -> u64 {
        self.left
    }
}

/// Opens a zip after checks a reader has to make before trusting the member list: at most
/// [`MAX_ZIP_ENTRIES`] entries, no two entries with the same part name (case-insensitive) or
/// hidden behind the same name, and no two entries sharing bytes (overlapping-entry zip bombs).
pub(crate) fn open_zip(bytes: &[u8]) -> Result<ZipArchive<Cursor<&[u8]>>> {
    // Every central directory entry starts with this signature, so this bounds the entry count
    // before the zip crate allocates anything per entry.
    let signatures = memchr::memmem::find_iter(bytes, b"PK\x01\x02").count();
    ensure!(signatures <= MAX_ZIP_ENTRIES, "zip has more than {MAX_ZIP_ENTRIES} entries");
    let mut ar = ZipArchive::new(Cursor::new(bytes)).context("reading zip")?;
    ensure!(ar.len() <= MAX_ZIP_ENTRIES, "zip has more than {MAX_ZIP_ENTRIES} entries");
    // The zip crate keeps one entry per exact name; the directory may list more.
    if let Some(n) = central_directory_count(bytes) {
        ensure!(n == ar.len() as u64, "zip directory lists {n} entries but only {} distinct names", ar.len());
    }
    let mut seen = HashSet::new();
    let mut spans = Vec::with_capacity(ar.len());
    for i in 0..ar.len() {
        let f = ar.by_index_raw(i)?;
        ensure!(seen.insert(opc::part_name(f.name())), "zip has two entries named {}", f.name());
        let end = f.data_start().checked_add(f.compressed_size()).context("zip entry size overflows")?;
        ensure!(end <= bytes.len() as u64, "zip entry {} runs past the end of the file", f.name());
        spans.push((f.header_start(), end));
    }
    spans.sort_unstable();
    for w in spans.windows(2) {
        ensure!(w[1].0 >= w[0].1, "zip entries overlap");
    }
    Ok(ar)
}

/// Total entry count from the end-of-central-directory record (zip64 if it says so).
fn central_directory_count(bytes: &[u8]) -> Option<u64> {
    let from = bytes.len().saturating_sub(22 + 65_535);
    let tail = &bytes[from..];
    let p = from + memchr::memmem::rfind(tail, b"PK\x05\x06")?;
    let eocd = bytes.get(p..p + 22)?;
    let n = u16::from_le_bytes([eocd[10], eocd[11]]);
    if n != 0xFFFF {
        return Some(n as u64);
    }
    let loc = bytes.get(p.checked_sub(20)?..p)?;
    if &loc[..4] != b"PK\x06\x07" {
        return Some(n as u64);
    }
    let off = u64::from_le_bytes(loc[8..16].try_into().ok()?) as usize;
    let rec = bytes.get(off..off.checked_add(56)?)?;
    if &rec[..4] != b"PK\x06\x06" {
        return None;
    }
    Some(u64::from_le_bytes(rec[32..40].try_into().ok()?))
}

/// The `[Content_Types].xml` member, found case-insensitively.
pub(crate) fn content_types_index(ar: &ZipArchive<Cursor<&[u8]>>) -> Option<usize> {
    (0..ar.len()).find(|&i| ar.name_for_index(i).is_some_and(|n| n.eq_ignore_ascii_case(CONTENT_TYPES)))
}

/// Content type of a VBA project part.
pub(crate) fn is_vba_project_type(ct: &str) -> bool {
    ct == "application/vnd.ms-office.vbaproject"
}

fn zip_vba(bytes: &[u8], f: &mut Facts, budget: &mut Budget, depth: usize) -> Result<()> {
    let mut ar = open_zip(bytes)?;
    let mut meta = Budget::new(META_BUDGET);
    let parts: Vec<String> = (0..ar.len()).map(|i| opc::part_name(ar.name_for_index(i).unwrap_or_default())).collect();
    let present: HashSet<String> = parts.iter().cloned().collect();
    let types = match content_types_index(&ar) {
        Some(i) => {
            let xml = budget.read(&mut ar, i, XML_CAP)?;
            Some(opc::ContentTypes::parse(opc::text(&xml)?, &present)?)
        }
        None => None,
    };
    for (i, part) in parts.iter().enumerate() {
        let ct = types.as_ref().and_then(|t| t.type_of(part));
        if is_macrosheet(part, ct) {
            f.xlm.push(format!("Excel 4.0 macro sheet {part}"));
        }
        if opc::rels_source(part).is_some() || part == "xl/workbook.xml" {
            // Small XML parts, read with their own small budget so they can neither starve the
            // VBA search of the shared one nor be used to keep the scanner decompressing.
            if let Ok(xml) = meta.read(&mut ar, i, META_PART_CAP) {
                if let Some(text) = xml_text(&xml) {
                    if part == "xl/workbook.xml" {
                        for n in opc::auto_run_names(&text).unwrap_or_default() {
                            f.xlm.push(format!("defined name {n} (runs a macro on open/close)"));
                        }
                    } else {
                        let _ = opc::relationships(&text, |r| {
                            if r.external && is_loading_rel(&r.kind_name()) && is_remote(&r.target) {
                                f.remote_templates.push(r.target.clone());
                            }
                        });
                    }
                }
            }
        }
        let claimed = part.ends_with("vbaproject.bin") || types.as_ref().and_then(|t| t.type_of(part)).is_some_and(is_vba_project_type);
        // A password-protected member of a plain zip cannot be read, and that alone says nothing
        // about macros (the archive check reports locked programs). Only a member that claims to
        // be a VBA project and cannot be read stays "unreadable".
        if ar.by_index_raw(i).map(|m| m.encrypted()).unwrap_or(false) {
            if claimed {
                f.vba_unreadable = true;
            }
            continue;
        }
        let head = budget.head(&mut ar, i)?;
        let is_ole = head.starts_with(&OLE_MAGIC);
        let is_zip = head.starts_with(ZIP_MAGIC);
        if !(claimed || is_ole || is_zip) {
            continue;
        }
        if depth >= MAX_NESTING {
            f.vba_unreadable = true;
            continue;
        }
        let Ok(inner) = budget.read(&mut ar, i, u64::MAX) else {
            f.vba_unreadable = true;
            continue;
        };
        if is_ole {
            ole_vba(&inner, f, budget, depth + 1);
        } else if is_zip {
            if zip_vba(&inner, f, budget, depth + 1).is_err() {
                f.vba_unreadable = true;
            }
        } else {
            // Says it is a VBA project but is not an OLE2 file: unreadable, not absent.
            f.vba_unreadable = true;
        }
    }
    Ok(())
}

/// An XML part as text: UTF-8, or UTF-16 with a byte-order mark (Office reads both, so an
/// attacker can pick UTF-16 to slip past a UTF-8-only reader).
fn xml_text(bytes: &[u8]) -> Option<String> {
    let utf16 = |b: &[u8], le: bool| {
        let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| if le { u16::from_le_bytes(*c) } else { u16::from_be_bytes(*c) }).collect();
        String::from_utf16(&units).ok()
    };
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, true);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, false);
    }
    opc::text(bytes).ok().map(str::to_string)
}

/// A SpreadsheetML Excel 4.0 macro sheet part, by content type or by its usual folder.
fn is_macrosheet(part: &str, ct: Option<&str>) -> bool {
    ct.is_some_and(|t| t.to_ascii_lowercase().contains("macrosheet"))
        || part.starts_with("xl/macrosheets/")
        || part.starts_with("xl/intlmacrosheets/")
}

/// External relationship kinds through which Office fetches something when the document opens:
/// a template (remote template injection), a frame or sub-document, or a linked OLE object
/// (CVE-2017-0199, "Follina" CVE-2022-30190).
fn is_loading_rel(kind: &str) -> bool {
    matches!(kind, "attachedtemplate" | "frame" | "subdocument" | "oleobject")
}

/// An address outside this computer's own disks: web, FTP, MHTML wrapping a web address
/// (CVE-2021-40444), or a network share in any spelling (`\\host\share`, `//host/share`,
/// `file://host/share`, `file:////host/share`). Local paths are not remote: `C:\...`,
/// `file:///C:/...`, `file://localhost/C:/...`, and the Windows long-path form `\\?\C:\...`.
pub(crate) fn is_remote(target: &str) -> bool {
    let mut t = target.trim().to_ascii_lowercase().replace('\\', "/");
    while let Some(rest) = t.strip_prefix("mhtml:").or_else(|| t.strip_prefix("ms-word:")) {
        t = rest.trim_start().to_string();
    }
    if ["http://", "https://", "ftp://"].iter().any(|p| t.starts_with(p)) {
        return true;
    }
    let had_file = t.starts_with("file:");
    let rest = t.strip_prefix("file:").unwrap_or(&t);
    let slashes = rest.len() - rest.trim_start_matches('/').len();
    let rest = rest.trim_start_matches('/');
    // `//?/c:/x` (long path) and `//?/unc/host/share` (a share).
    if let Some(after) = rest.strip_prefix("?/").or_else(|| rest.strip_prefix("./")) {
        return after.starts_with("unc/");
    }
    let drive = |s: &str| matches!(s.as_bytes(), [_, b':' | b'|', ..]);
    if drive(rest) {
        return false;
    }
    if had_file {
        // file:x, file:/x and file:///x name this machine; file://host/x names a host (local
        // when it is empty or localhost); four or more slashes are a UNC path (file:////host/x).
        let host = rest.split('/').next().unwrap_or("");
        return match slashes {
            0 | 1 | 3 => false,
            2 => !host.is_empty() && host != "localhost",
            _ => true,
        };
    }
    // Two leading slashes (from `\\` or `//`) and a host: a network share.
    slashes >= 2 && !rest.is_empty()
}

/// True for an OLE2 file whose root holds a VBA project directly (`/VBA/dir`): a bare
/// vbaProject.bin, whatever it is named, as opposed to a document that contains one.
pub(crate) fn is_bare_vba_project(bytes: &[u8]) -> bool {
    let Ok(comp) = cfb::CompoundFile::open(Cursor::new(bytes)) else { return false };
    let found = comp.walk().any(|e| {
        e.is_stream() && e.name().eq_ignore_ascii_case("dir") && e.path().parent().and_then(Path::parent) == Some(Path::new("/"))
    });
    found
}

fn ole_vba(bytes: &[u8], f: &mut Facts, budget: &mut Budget, depth: usize) {
    if ole_vba_inner(bytes, f, budget, depth).is_err() {
        f.vba_unreadable = true;
    }
}

fn ole_vba_inner(bytes: &[u8], f: &mut Facts, budget: &mut Budget, depth: usize) -> Result<()> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(bytes)).context("reading OLE2 file")?;
    let entries: Vec<(PathBuf, bool, u64)> = comp.walk().map(|e| (e.path().to_path_buf(), e.is_stream(), e.len())).collect();
    let name_is = |p: &Path, n: &str| p.file_name().is_some_and(|s| s.to_string_lossy().eq_ignore_ascii_case(n));
    // A VBA storage with a compiled project but no `dir` stream cannot be listed: unreadable.
    for (p, is_stream, _) in &entries {
        if *is_stream && name_is(p, "_VBA_PROJECT") {
            let vba = p.parent().unwrap_or(Path::new("/"));
            if !entries.iter().any(|(q, s, _)| *s && q.parent() == Some(vba) && name_is(q, "dir")) {
                f.vba_unreadable = true;
            }
        }
    }
    let dirs: Vec<PathBuf> = entries.iter().filter(|(p, s, _)| *s && name_is(p, "dir")).map(|(p, _, _)| p.clone()).collect();
    for dir_path in dirs {
        let Some(vba_storage) = dir_path.parent().map(|p| p.to_path_buf()) else { continue };
        let Ok(dir_raw) = read_stream(&mut comp, &dir_path, budget) else {
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
            let source = read_stream(&mut comp, &stream, budget)
                .ok()
                .and_then(|raw| raw.get(m.text_offset as usize..).map(|s| s.to_vec()))
                .and_then(|s| ovba::decompress(&s).ok());
            match source {
                Some(src) => f.vba.push(VbaModule { name: m.name, bytes: src.len(), source: ovba::latin1(&src) }),
                None => f.vba_unreadable = true,
            }
        }
    }
    // Excel 4.0 macros in a BIFF8 workbook (the same check the cleaner refuses on). An encrypted
    // or unusual stream cannot be listed; VBA, if any, is still reported above.
    // Any Workbook stream, also one embedded in a Word file's ObjectPool. Read on its own budget,
    // so a large ordinary workbook does not leave too little for the embedded objects below.
    for (p, is_stream, _) in &entries {
        if *is_stream && name_is(p, "Workbook") {
            let mut own = Budget::new(WORKBOOK_CAP);
            let Ok(data) = read_stream(&mut comp, p, &mut own) else { continue };
            match crate::clean::biff::xlm_macros(&data) {
                Ok(found) => f.xlm.extend(found),
                Err(e) if format!("{e:#}").contains("encrypted") => f.workbook_encrypted = true,
                Err(_) => {}
            }
        }
    }
    // Streams that are whole files themselves (an embedded workbook's Package stream, ...).
    for (p, is_stream, len) in &entries {
        if !*is_stream || *len < 8 {
            continue;
        }
        let mut head = [0u8; 8];
        if comp.open_stream(p).and_then(|mut s| s.read_exact(&mut head)).is_err() {
            f.vba_unreadable = true;
            continue;
        }
        let nested_ole = head == OLE_MAGIC;
        let nested_zip = head.starts_with(ZIP_MAGIC);
        if !(nested_ole || nested_zip) {
            continue;
        }
        if depth >= MAX_NESTING {
            f.vba_unreadable = true;
            continue;
        }
        let Ok(inner) = read_stream(&mut comp, p, budget) else {
            f.vba_unreadable = true;
            continue;
        };
        if nested_ole {
            ole_vba(&inner, f, budget, depth + 1);
        } else if zip_vba(&inner, f, budget, depth + 1).is_err() {
            f.vba_unreadable = true;
        }
    }
    Ok(())
}

fn read_stream(comp: &mut cfb::CompoundFile<Cursor<&[u8]>>, path: &Path, budget: &mut Budget) -> Result<Vec<u8>> {
    let s = comp.open_stream(path)?;
    let len = s.len();
    if len > budget.left() {
        bail!("stream {} is over the read budget", path.display());
    }
    let mut buf = Vec::new();
    s.take(len).read_to_end(&mut buf)?;
    budget.charge(buf.len() as u64)?;
    Ok(buf)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Seek, Write};
    use zip::write::SimpleFileOptions;

    /// A CompressedContainer holding `raw` in one uncompressed chunk (header 0x3FFF).
    fn container(raw: &[u8]) -> Vec<u8> {
        assert!(raw.len() <= 4096);
        let mut v = vec![0x01, 0xFF, 0x3F];
        v.extend_from_slice(raw);
        v
    }

    fn dir_record(id: u16, data: &[u8]) -> Vec<u8> {
        let mut v = id.to_le_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    /// Writes `<root>/PROJECT`, `<root>/VBA/dir` and one stream per module into `comp`.
    pub fn write_vba<F: Read + Write + Seek>(comp: &mut cfb::CompoundFile<F>, root: &str, modules: &[(&str, &str)]) {
        let base = PathBuf::from(root);
        if root != "/" {
            comp.create_storage_all(&base).unwrap();
        }
        comp.create_storage(base.join("VBA")).unwrap();
        let mut dir = Vec::new();
        for (name, _) in modules {
            dir.extend(dir_record(0x0019, name.as_bytes()));
            dir.extend(dir_record(0x001A, name.as_bytes()));
            dir.extend(dir_record(0x0031, &0u32.to_le_bytes()));
            dir.extend(dir_record(0x002B, &[]));
        }
        dir.extend(dir_record(0x0010, &[]));
        comp.create_stream(base.join("VBA/dir")).unwrap().write_all(&container(&dir)).unwrap();
        for (name, src) in modules {
            comp.create_stream(base.join("VBA").join(name)).unwrap().write_all(&container(src.as_bytes())).unwrap();
        }
        comp.create_stream(base.join("PROJECT")).unwrap().write_all(b"ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n").unwrap();
    }

    pub const WORM: &str = "Attribute VB_Name = \"Kangatang\"\r\nSub Auto_Open()\r\nApplication.OnSheetActivate = \"x\"\r\nEnd Sub\r\n";

    pub fn vba_project_bin() -> Vec<u8> {
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        write_vba(&mut comp, "/", &[("Kangatang", WORM)]);
        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

    pub fn zip_of(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in parts {
            w.start_file(*name, SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated)).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn oversized_relationship_parts_cannot_starve_the_vba_search() {
        // 60 relationship parts of 2 MB of spaces each (tiny when deflated) before the project:
        // 120 MB if read in full. Each is capped at 1 MB on its own 8 MB budget, so the VBA
        // project after them is still found and the scan stays quick.
        let big = vec![b' '; 2 * 1024 * 1024];
        let names: Vec<String> = (0..60).map(|i| format!("word/_rels/p{i}.xml.rels")).collect();
        let bin = vba_project_bin();
        let mut parts: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), big.as_slice())).collect();
        parts.push(("word/vbaProject.bin", &bin));
        let started = std::time::Instant::now();
        let f = facts(&zip_of(&parts));
        assert_eq!(f.vba.len(), 1, "the VBA project after the big parts is still read");
        assert!(!f.vba_unreadable);
        assert!(started.elapsed().as_secs() < 20, "took {:?}", started.elapsed());
    }

    #[test]
    fn finds_vba_in_any_ole_member_whatever_its_name() {
        let bin = vba_project_bin();
        let f = facts(&zip_of(&[("[Content_Types].xml", b"<Types/>"), ("xl/data.bin", &bin)]));
        assert_eq!(f.vba.len(), 1);
        assert_eq!(f.vba[0].name, "Kangatang");
        assert!(is_bare_vba_project(&bin));
    }

    #[test]
    fn claimed_vba_part_that_is_not_ole_is_unreadable() {
        let ct = br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/x.dat" ContentType="application/vnd.ms-office.vbaProject"/></Types>"#;
        let f = facts(&zip_of(&[("[content_types].xml", ct), ("xl/x.dat", b"\x00\x00not ole at all")]));
        assert!(f.vba_unreadable);
        // Truncated OLE2 file: unreadable.
        let bin = vba_project_bin();
        let f = facts(&zip_of(&[("xl/vbaProject.bin", &bin[..600])]));
        assert!(f.vba_unreadable && f.vba.is_empty());
    }

    #[test]
    fn nested_package_vba_is_found() {
        let inner = zip_of(&[("xl/whatever.bin", &vba_project_bin())]);
        let outer = zip_of(&[("word/embeddings/Book1.xlsm", &inner)]);
        assert_eq!(facts(&outer).vba.len(), 1);
    }

    #[test]
    fn broken_zip_is_unreadable_not_clean() {
        let mut z = zip_of(&[("a.xml", b"<a/>")]);
        z.truncate(z.len() - 10);
        assert!(facts(&z).vba_unreadable);
    }

    #[test]
    fn budget_overrun_is_unreadable() {
        // A deflated member that expands past the budget: reported, never read to the end.
        let mut ole = OLE_MAGIC.to_vec();
        ole.extend_from_slice(&vec![0u8; 3 * 1024 * 1024]);
        let z = zip_of(&[("xl/a.bin", &ole)]);
        assert!(z.len() < 64 * 1024, "fixture must be small on disk");
        let mut f = Facts::default();
        let mut b = Budget::new(1024 * 1024);
        zip_vba(&z, &mut f, &mut b, 0).unwrap();
        assert!(f.vba_unreadable);
    }

    #[test]
    fn duplicate_and_overlapping_entries_are_refused() {
        let z = zip_of(&[("a.xml", b"<a/>"), ("A.XML", b"<b/>")]);
        assert!(open_zip(&z).is_err());
        assert!(facts(&z).vba_unreadable);
        // Two directory entries pointing at the same local entry.
        let z = zip_of(&[("a.xml", b"<a/>"), ("b.xml", b"<b/>")]);
        let cd: Vec<usize> = memchr::memmem::find_iter(&z, b"PK\x01\x02").collect();
        let mut z2 = z.clone();
        let first_offset = z[cd[0] + 42..cd[0] + 46].to_vec();
        z2[cd[1] + 42..cd[1] + 46].copy_from_slice(&first_offset);
        assert!(open_zip(&z2).is_err());
        // Same exact name twice: the zip crate shows one, the directory lists two.
        let z = zip_of(&[("a.xml", b"<a/>"), ("b.xml", b"<b/>")]);
        let mut z3 = z.clone();
        let name_at = cd[1] + 46;
        z3[name_at] = b'a';
        assert!(open_zip(&z3).is_err());
    }
}
