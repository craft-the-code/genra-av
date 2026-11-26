//! Writes a macro-free copy of an Office file, keeping its data and formatting. This is the engine
//! behind "Dọn sạch giúp tôi". It parses and rewrites containers only; it never runs anything and
//! never touches the original bytes it was given.
//!
//! - OOXML (.xlsm/.docm/.pptm, or a renamed .xlsx carrying macros): the zip is rebuilt without the
//!   VBA parts, their relationships and content-type entries, and the main part switches to the
//!   plain (macro-free) content type. VBA parts are found by relationship type, by content type
//!   (Override or Default) and by content (an OLE2 member holding a VBA project), never by name
//!   alone; `.rels` and `[Content_Types].xml` are parsed with a namespace-aware XML reader and
//!   re-serialised. A remote `attachedTemplate` (template injection) is removed with its reference
//!   in the settings part; an embedded OLE2 object with its own VBA project is cleaned in place.
//!   Excel 4.0 macro sheets, auto-run defined names, macro-enabled add-ins and embedded packages
//!   with macros are refused with an error. Every other part is copied raw, byte for byte.
//! - OLE2 (.xls, .doc): the compound file is rewritten without the VBA project storage
//!   (`_VBA_PROJECT_CUR`, `Macros`); every other stream is copied unchanged. In an .xls, the
//!   Workbook stream also loses its OBJPROJ marker and its "Visual Basic module" sheets (see
//!   [`biff`]); if anything there looks unusual the Workbook stream is copied unchanged instead.
//!
//!   A Workbook with Excel 4.0 macro sheets (BoundSheet type 0x01) or Auto_Open/Auto_Close names,
//!   an encrypted Workbook (its sheet list cannot be checked) and a BIFF5 `Book` are refused.
//!
//! The result is checked with [`crate::extract::facts`] (and, for OOXML, for macro-enabled
//! content types, macro sheets and remote templates): if anything is still visible, `clean` fails
//! rather than hand back a file that only looks clean. Zip input gets the same budget as the
//! scanner: [`crate::extract::ZIP_BUDGET`] decompressed bytes, [`crate::extract::MAX_ZIP_ENTRIES`]
//! entries, no duplicate or overlapping entries.

use crate::extract::{self, Kind};
use anyhow::{bail, ensure, Context, Result};
use std::collections::HashSet;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

/// Inputs above this are refused: Office documents worth cleaning are far smaller.
pub const MAX_INPUT: usize = 200 * 1024 * 1024;

#[derive(Debug)]
pub struct Cleaned {
    pub bytes: Vec<u8>,
    /// Extension the cleaned copy should carry (`xlsx` for an .xlsm, ...); `None` keeps the
    /// original one (.xls and .doc stay what they are).
    pub new_extension: Option<&'static str>,
    /// Human-readable list of what was removed, e.g. "VBA project", "module sheet Kangatang".
    pub removed: Vec<String>,
    /// What was deliberately left in place and why, for the report shown to the user.
    pub kept: Vec<String>,
}

pub fn clean(bytes: &[u8]) -> Result<Cleaned> {
    check_size(bytes.len())?;
    let before = extract::facts(bytes);
    let mut out = match extract::kind(bytes) {
        Kind::Zip => ooxml::clean(bytes)?,
        Kind::Ole => ole::clean(bytes)?,
        Kind::Other => bail!("not an Office file (neither OLE2 nor OOXML)"),
    };
    if !before.vba.is_empty() {
        let names: Vec<&str> = before.vba.iter().map(|m| m.name.as_str()).collect();
        if let Some(first) = out.removed.iter_mut().find(|r| r.starts_with("VBA project ") && !r.starts_with("VBA project signature")) {
            first.push_str(&format!(" (modules: {})", names.join(", ")));
        }
    }
    let after = extract::facts(&out.bytes);
    if !after.vba.is_empty() || after.vba_unreadable {
        bail!("VBA is still present after cleaning; this file layout is not supported yet");
    }
    Ok(out)
}

fn check_size(len: usize) -> Result<()> {
    if len > MAX_INPUT {
        bail!("file is over {} MB; refusing to clean it", MAX_INPUT / 1024 / 1024);
    }
    Ok(())
}

mod ooxml {
    use super::*;
    use crate::extract::{opc, Budget, OLE_MAGIC, XML_CAP, ZIP_BUDGET, ZIP_MAGIC};
    use std::collections::HashMap;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipArchive, ZipWriter};

    /// Macro-enabled main part content type (lowercase) → plain one, and the extension that goes
    /// with it.
    const MAIN_TYPES: &[(&str, &str, &str)] = &[
        (
            "application/vnd.ms-excel.sheet.macroenabled.main+xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
            "xlsx",
        ),
        (
            "application/vnd.ms-excel.template.macroenabled.main+xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
            "xltx",
        ),
        (
            "application/vnd.ms-word.document.macroenabled.main+xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            "docx",
        ),
        (
            "application/vnd.ms-word.template.macroenabledtemplate.main+xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
            "dotx",
        ),
        (
            "application/vnd.ms-powerpoint.presentation.macroenabled.main+xml",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
            "pptx",
        ),
        (
            "application/vnd.ms-powerpoint.slideshow.macroenabled.main+xml",
            "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml",
            "ppsx",
        ),
        (
            "application/vnd.ms-powerpoint.template.macroenabled.main+xml",
            "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml",
            "potx",
        ),
    ];
    /// .xlsb has no macro-free main type: this one is used with and without VBA.
    const XLSB_MAIN: &str = "application/vnd.ms-excel.sheet.binary.macroenabled.main";

    /// VBA project, its signatures, and the Word parts that only serve it.
    fn vba_type_label(ct: &str) -> Option<&'static str> {
        if extract::is_vba_project_type(ct) {
            Some("VBA project")
        } else if ct.starts_with("application/vnd.ms-office.vbaprojectsignature") {
            Some("VBA project signature")
        } else {
            match ct {
                "application/vnd.ms-word.vbadata+xml" => Some("VBA data"),
                "application/vnd.ms-word.keymapcustomizations+xml" => Some("VBA key bindings"),
                "application/vnd.ms-word.attachedtoolbars" => Some("VBA toolbars"),
                _ => None,
            }
        }
    }

    fn vba_rel_label(kind_name: &str) -> Option<&'static str> {
        if kind_name == "vbaproject" {
            Some("VBA project")
        } else if kind_name.starts_with("vbaproject") {
            Some("VBA project signature")
        } else {
            match kind_name {
                "wordvbadata" => Some("VBA data"),
                "keymapcustomizations" => Some("VBA key bindings"),
                "attachedtoolbars" => Some("VBA toolbars"),
                _ => None,
            }
        }
    }

    fn vba_name_label(part: &str) -> Option<&'static str> {
        let base = part.rsplit('/').next().unwrap_or(part);
        if base == "vbaproject.bin" {
            Some("VBA project")
        } else if base.starts_with("vbaprojectsignature") && base.ends_with(".bin") {
            Some("VBA project signature")
        } else if base == "vbadata.xml" {
            Some("VBA data")
        } else {
            None
        }
    }

    fn is_macrosheet(part: &str, ct: Option<&str>) -> bool {
        ct.is_some_and(|t| t.contains("macrosheet")) || part.starts_with("xl/macrosheets/") || part.starts_with("xl/intlmacrosheets/")
    }

    fn is_macro_main_type(ct: &str) -> bool {
        ct.contains("macroenabled") && ct.contains(".main") && ct != XLSB_MAIN
    }

    fn is_spreadsheet_main(ct: &str) -> bool {
        ct.starts_with("application/vnd.openxmlformats-officedocument.spreadsheetml.") && ct.ends_with(".main+xml")
            || ct.starts_with("application/vnd.ms-excel.") && ct.contains("macroenabled.main+xml")
    }

    /// External relationship types that fetch content when the file opens. Only the template one
    /// is removed (it is how remote macros are pulled in); the others are reported as kept.
    const REMOTE_KINDS: &[&str] = &["oleobject", "frame", "subdocument"];

    struct Package<'a> {
        ar: ZipArchive<Cursor<&'a [u8]>>,
        names: Vec<String>,
        parts: Vec<String>,
        ct_index: usize,
        types: opc::ContentTypes,
    }

    fn open<'a>(bytes: &'a [u8], budget: &mut Budget) -> Result<Package<'a>> {
        let mut ar = extract::open_zip(bytes)?;
        let names: Vec<String> = (0..ar.len()).map(|i| ar.name_for_index(i).unwrap_or_default().to_string()).collect();
        let parts: Vec<String> = names.iter().map(|n| opc::part_name(n)).collect();
        let present: HashSet<String> = parts.iter().cloned().collect();
        let ct_index = extract::content_types_index(&ar).context("no [Content_Types].xml: not an Office Open XML package")?;
        let xml = read_xml(&mut ar, ct_index, budget)?;
        let types = opc::ContentTypes::parse(&xml, &present).context("reading [Content_Types].xml")?;
        Ok(Package { ar, names, parts, ct_index, types })
    }

    fn read_xml(ar: &mut ZipArchive<Cursor<&[u8]>>, i: usize, budget: &mut Budget) -> Result<String> {
        let name = ar.name_for_index(i).unwrap_or_default().to_string();
        let bytes = budget.read(ar, i, XML_CAP)?;
        Ok(opc::text(&bytes).with_context(|| format!("reading {name}"))?.to_string())
    }

    pub fn clean(bytes: &[u8]) -> Result<Cleaned> {
        clean_with_budget(bytes, ZIP_BUDGET)
    }

    pub(super) fn clean_with_budget(bytes: &[u8], total: u64) -> Result<Cleaned> {
        let mut budget = Budget::new(total);
        let mut pkg = open(bytes, &mut budget)?;
        let n = pkg.names.len();
        let mut removed = Vec::new();
        let mut kept = Vec::new();
        let mut problems = Vec::new();

        // Parts to drop, with what they are. Found by name, by content type, by relationship type
        // and by content (an OLE2 member holding a bare VBA project), never by name alone.
        let mut doomed: HashMap<String, &'static str> = HashMap::new();
        for (part, name) in pkg.parts.iter().zip(&pkg.names) {
            let ct = pkg.types.type_of(part);
            if let Some(label) = ct.and_then(vba_type_label).or_else(|| vba_name_label(part)) {
                doomed.entry(part.clone()).or_insert(label);
            }
            if is_macrosheet(part, ct) {
                problems.push(format!("Excel 4.0 macro sheet {name}"));
            }
        }
        // Word settings part → ids of remote attachedTemplate relationships removed from it.
        let mut templates: HashMap<String, HashSet<String>> = HashMap::new();
        for i in 0..n {
            let Some(source) = opc::rels_source(&pkg.parts[i]) else { continue };
            let xml = read_xml(&mut pkg.ar, i, &mut budget)?;
            let name = &pkg.names[i];
            opc::relationships(&xml, |r| {
                let kind = r.kind_name();
                if let Some(label) = vba_rel_label(&kind) {
                    if !r.external {
                        doomed.entry(opc::resolve(&source, &r.target)).or_insert(label);
                    }
                }
                if kind.contains("macrosheet") {
                    problems.push(format!("Excel 4.0 macro sheet relationship {} in {name}", r.id));
                }
                if kind == "attachedtemplate" && r.external {
                    templates.entry(source.clone()).or_default().insert(r.id.clone());
                }
                if r.external && REMOTE_KINDS.contains(&kind.as_str()) {
                    kept.push(format!("external {kind} link to {} in {name}: kept, it is a link, not a macro", r.target));
                }
            })
            .with_context(|| format!("reading {name}"))?;
        }

        // Members that are containers themselves: OLE2 objects and embedded packages.
        let mut replaced: HashMap<usize, Vec<u8>> = HashMap::new();
        for i in 0..n {
            let part = pkg.parts[i].clone();
            let name = pkg.names[i].clone();
            if doomed.contains_key(&part) || i == pkg.ct_index {
                continue;
            }
            let head = budget.head(&mut pkg.ar, i)?;
            if head.starts_with(&OLE_MAGIC) {
                let data = budget.read(&mut pkg.ar, i, u64::MAX)?;
                let f = extract::facts(&data);
                if f.vba.is_empty() && !f.vba_unreadable {
                    continue;
                }
                if extract::is_bare_vba_project(&data) {
                    doomed.insert(part, "VBA project");
                    continue;
                }
                // An embedded document (oleObject, ActiveX data, ...) with its own VBA project:
                // cleaned in place, so whatever refers to the part still finds it.
                let inner = ole::clean(&data).with_context(|| format!("embedded object {name} carries VBA that cannot be removed"))?;
                let after = extract::facts(&inner.bytes);
                ensure!(after.vba.is_empty() && !after.vba_unreadable, "embedded object {name} still carries VBA after cleaning");
                removed.extend(inner.removed.iter().map(|r| format!("{r} inside embedded object {name}")));
                kept.extend(inner.kept.iter().map(|k| format!("{k} (embedded object {name})")));
                replaced.insert(i, inner.bytes);
            } else if head.starts_with(ZIP_MAGIC) {
                let data = budget.read(&mut pkg.ar, i, u64::MAX)?;
                let f = extract::facts(&data);
                if !f.vba.is_empty() || f.vba_unreadable {
                    problems.push(format!("embedded package {name} carries its own VBA project"));
                }
                problems.extend(macro_problems(&data)?.into_iter().map(|p| format!("{p} (inside embedded package {name})")));
            }
        }
        // A dropped part's own relationships go with it (vbaProject.bin.rels → signature).
        for part in &pkg.parts {
            if opc::rels_source(part).is_some_and(|src| doomed.contains_key(&src)) {
                doomed.entry(part.clone()).or_insert("relationships of a removed VBA part");
            }
        }
        if !problems.is_empty() {
            bail!("cannot make this file macro-free: {}", problems.join("; "));
        }

        let mut out = ZipWriter::new(Cursor::new(Vec::new()));
        for i in 0..n {
            let name = pkg.names[i].clone();
            let part = pkg.parts[i].clone();
            if let Some(label) = doomed.get(&part) {
                removed.push(format!("{label} {name}"));
                continue;
            }
            let replacement: Option<Vec<u8>> = if let Some(b) = replaced.remove(&i) {
                Some(b)
            } else if i == pkg.ct_index {
                let xml = read_xml(&mut pkg.ar, i, &mut budget)?;
                rewrite_content_types(&xml, &doomed, &mut removed)?.map(String::into_bytes)
            } else if let Some(source) = opc::rels_source(&part) {
                let xml = read_xml(&mut pkg.ar, i, &mut budget)?;
                let filtered = opc::filter_relationships(&xml, |r| {
                    let kind = r.kind_name();
                    vba_rel_label(&kind).is_some()
                        || (kind == "attachedtemplate" && r.external)
                        || (!r.external && doomed.contains_key(&opc::resolve(&source, &r.target)))
                })
                .with_context(|| format!("rewriting {name}"))?;
                filtered.map(|(text, dropped)| {
                    let mut plain = 0;
                    for r in dropped {
                        if r.kind_name() == "attachedtemplate" {
                            removed.push(format!("remote template link {} in {name} (template injection)", r.target));
                        } else {
                            plain += 1;
                        }
                    }
                    if plain > 0 {
                        removed.push(format!("{plain} relationship(s) to VBA parts in {name}"));
                    }
                    text.into_bytes()
                })
            } else if let Some(ids) = templates.get(&part) {
                let xml = read_xml(&mut pkg.ar, i, &mut budget)?;
                let new = opc::drop_attached_template(&xml, ids).with_context(|| format!("rewriting {name}"))?;
                if new.is_some() {
                    removed.push(format!("attachedTemplate reference in {name}"));
                }
                new.map(String::into_bytes)
            } else {
                None
            };
            match replacement {
                Some(data) => {
                    let src = pkg.ar.by_index_raw(i)?;
                    let mut opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
                    if let Some(t) = src.last_modified() {
                        opts = opts.last_modified_time(t);
                    }
                    drop(src);
                    out.start_file(name.as_str(), opts)?;
                    out.write_all(&data)?;
                }
                None => out.raw_copy_file(pkg.ar.by_index_raw(i)?)?,
            }
        }
        let bytes = out.finish()?.into_inner();
        let left = macro_problems(&bytes)?;
        if !left.is_empty() {
            bail!("macros are still present after cleaning: {}", left.join("; "));
        }
        let new_extension = main_extension(&bytes)?;
        Ok(Cleaned { bytes, new_extension, removed, kept })
    }

    fn rewrite_content_types(xml: &str, doomed: &HashMap<String, &'static str>, removed: &mut Vec<String>) -> Result<Option<String>> {
        let mut dropped_overrides = 0;
        let mut notes = Vec::new();
        let out = opc::rewrite_content_types(xml, |e| match e {
            opc::CtEntry::Override { part, typ } => {
                if doomed.contains_key(part) || vba_type_label(typ).is_some() {
                    dropped_overrides += 1;
                    opc::CtAction::Drop
                } else if let Some((m, plain, _)) = MAIN_TYPES.iter().find(|(m, _, _)| *m == typ) {
                    notes.push(format!("macro-enabled main content type ({m} → {plain})"));
                    opc::CtAction::SetType(plain.to_string())
                } else {
                    opc::CtAction::Keep
                }
            }
            opc::CtEntry::Default { ext, typ } => {
                if vba_type_label(typ).is_some() {
                    notes.push(format!("default VBA content type for *.{ext}"));
                    opc::CtAction::Drop
                } else if let Some((m, plain, _)) = MAIN_TYPES.iter().find(|(m, _, _)| *m == typ) {
                    notes.push(format!("macro-enabled default content type for *.{ext} ({m} → {plain})"));
                    opc::CtAction::SetType(plain.to_string())
                } else {
                    opc::CtAction::Keep
                }
            }
        })
        .context("rewriting [Content_Types].xml")?;
        if dropped_overrides > 0 {
            removed.push(format!("{dropped_overrides} content-type override(s) for VBA parts"));
        }
        removed.extend(notes);
        Ok(out)
    }

    /// What in a package can still run a macro: VBA parts, a macro-enabled main content type,
    /// Excel 4.0 macro sheets, auto-run defined names, remote templates, nested packages with any
    /// of these. Empty for a package that is not OOXML (no content types).
    pub(super) fn macro_problems(bytes: &[u8]) -> Result<Vec<String>> {
        let mut budget = Budget::new(ZIP_BUDGET);
        let mut pkg = match open(bytes, &mut budget) {
            Ok(p) => p,
            Err(_) if extract::open_zip(bytes).is_ok_and(|ar| extract::content_types_index(&ar).is_none()) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for (t, what) in pkg.types.defaults.values().map(|t| (t, "default")).chain(pkg.types.overrides.values().map(|t| (t, "override"))) {
            if is_macro_main_type(t) {
                out.push(format!("macro-enabled content type {t} ({what})"));
            }
        }
        for i in 0..pkg.parts.len() {
            let part = pkg.parts[i].clone();
            let name = pkg.names[i].clone();
            let ct = pkg.types.type_of(&part).map(str::to_string);
            if ct.as_deref().and_then(vba_type_label).is_some() {
                out.push(format!("VBA part {name}"));
            }
            if is_macrosheet(&part, ct.as_deref()) {
                out.push(format!("Excel 4.0 macro sheet {name}"));
            }
            if ct.as_deref().is_some_and(is_spreadsheet_main) {
                let xml = read_xml(&mut pkg.ar, i, &mut budget)?;
                for n in opc::auto_run_names(&xml).with_context(|| format!("reading {name}"))? {
                    out.push(format!("defined name {n} in {name} runs a macro when the workbook opens or closes"));
                }
            }
            if opc::rels_source(&part).is_some() {
                let xml = read_xml(&mut pkg.ar, i, &mut budget)?;
                opc::relationships(&xml, |r| {
                    let kind = r.kind_name();
                    if vba_rel_label(&kind).is_some() {
                        out.push(format!("VBA relationship {} in {name}", r.id));
                    }
                    if kind.contains("macrosheet") {
                        out.push(format!("Excel 4.0 macro sheet relationship {} in {name}", r.id));
                    }
                    if kind == "attachedtemplate" && r.external {
                        out.push(format!("remote template {} in {name}", r.target));
                    }
                })
                .with_context(|| format!("reading {name}"))?;
            }
        }
        Ok(out)
    }

    /// Extension matching the main part's content type in the written package.
    fn main_extension(bytes: &[u8]) -> Result<Option<&'static str>> {
        let mut budget = Budget::new(ZIP_BUDGET);
        let pkg = open(bytes, &mut budget)?;
        for t in pkg.types.overrides.values() {
            if let Some((_, _, ext)) = MAIN_TYPES.iter().find(|(_, plain, _)| plain.eq_ignore_ascii_case(t)) {
                return Ok(Some(ext));
            }
        }
        Ok(None)
    }
}

mod ole {
    use super::*;

    pub fn clean(bytes: &[u8]) -> Result<Cleaned> {
        let mut src = cfb::CompoundFile::open(Cursor::new(bytes)).context("reading OLE2 file")?;
        let entries: Vec<cfb::Entry> = src.walk().collect();
        if entries.iter().any(|e| e.is_stream() && e.path() == Path::new("/PowerPoint Document")) {
            bail!("PowerPoint 97-2003 (.ppt) keeps VBA inside the PowerPoint Document stream; not supported yet");
        }
        let has = |p: &str| entries.iter().any(|e| e.is_stream() && e.path() == Path::new(p));
        if has("/Book") && !has("/Workbook") {
            bail!("Excel 5.0/95 workbook (BIFF5 Book stream): not supported, its macro sheets cannot be checked");
        }
        let mut removed = Vec::new();
        let mut kept = Vec::new();

        // VBA project storages: the parent of each `VBA` storage holding a `dir` stream, plus any
        // `_VBA_PROJECT_CUR` / root `Macros` storage even if its `dir` is missing or broken.
        let mut doomed: Vec<PathBuf> = Vec::new();
        for e in &entries {
            let p = e.path();
            let candidate = if e.is_stream() && e.name().eq_ignore_ascii_case("dir") {
                p.parent().and_then(|vba| vba.parent()).map(Path::to_path_buf)
            } else if e.is_storage()
                && (e.name().eq_ignore_ascii_case("_VBA_PROJECT_CUR")
                    || (e.name().eq_ignore_ascii_case("Macros") && p.parent() == Some(Path::new("/"))))
            {
                Some(p.to_path_buf())
            } else {
                None
            };
            if let Some(c) = candidate {
                if c == Path::new("/") {
                    bail!("the file is a bare VBA project, not a document");
                }
                if !doomed.iter().any(|d| c.starts_with(d)) {
                    doomed.retain(|d| !d.starts_with(&c));
                    doomed.push(c);
                }
            }
        }
        for d in &doomed {
            removed.push(format!("VBA project {}", d.display().to_string().trim_start_matches('/')));
        }

        let mut out = cfb::CompoundFile::create_with_version(src.version(), Cursor::new(Vec::new()))?;
        out.set_storage_clsid("/", *src.root_entry().clsid())?;
        out.set_state_bits("/", src.root_entry().state_bits())?;
        for e in &entries {
            let p = e.path();
            if e.is_root() || doomed.iter().any(|d| p.starts_with(d)) {
                continue;
            }
            if e.is_storage() {
                out.create_storage(p)?;
                out.set_storage_clsid(p, *e.clsid())?;
                out.set_state_bits(p, e.state_bits())?;
                continue;
            }
            let mut data = Vec::new();
            src.open_stream(p)?.read_to_end(&mut data)?;
            if p == Path::new("/Workbook") {
                let xlm = biff::xlm_macros(&data).context("cannot check the Workbook stream for Excel 4.0 macros")?;
                if !xlm.is_empty() {
                    bail!("cannot make this file macro-free: {}", xlm.join("; "));
                }
                match biff::strip(&data) {
                    Ok(s) => {
                        removed.extend(s.removed);
                        data = s.bytes;
                    }
                    Err(err) => kept.push(format!(
                        "Workbook stream copied unchanged ({err:#}); any OBJPROJ marker and empty \"Visual Basic module\" sheet entries stay, \
                         without code: Excel shows no macros and an empty module sheet may still be listed"
                    )),
                }
            }
            let mut s = out.create_stream(p)?;
            s.write_all(&data)?;
            drop(s);
            out.set_state_bits(p, e.state_bits())?;
        }
        out.flush()?;
        let bytes = out.into_inner().into_inner();
        Ok(Cleaned { bytes, new_extension: None, removed, kept })
    }

}

/// BIFF8 Workbook stream edits per [MS-XLS]. Without the VBA storage, two things in the stream
/// still speak of macros:
///
/// - **OBJPROJ** (0x00D3, no data) says "this workbook has a VBA project". Removed.
/// - **BoundSheet8 with dt = 0x06** ("Visual Basic module") plus its substream (BOF dt 0x0006 ..
///   EOF). In BIFF8 the substream holds only page-setup records; the code lives in the VBA
///   storage. Removed, because a module sheet whose module is gone is exactly what a reader
///   should never be asked to interpret.
///
/// Removing records moves every later byte, so absolute stream offsets are recomputed:
/// BoundSheet8.lbPlyPos, Index.ibXF and Index.rgibRw, ExtSST.ISSTINF.ib. Removing a sheet also
/// shifts sheet indices, so TabId, the self-referencing SupBook (ctab), ExternSheet XTI
/// itabFirst/itabLast (an XTI that covered only the module sheet becomes 0xFFFF, "deleted sheet"),
/// Lbl.itab and Window1 itabCur/itabFirst/ctabSel are rewritten. Anything
/// that does not fit these expectations (encryption, a CONTINUE where none is expected, a defined
/// name scoped to the module sheet) is an error, and the caller keeps the stream
/// unchanged. CODENAME records stay: an .xlsx keeps code names too and they run nothing.
pub(crate) mod biff {
    use anyhow::{bail, ensure, Context, Result};

    const BOF: u16 = 0x0809;
    const EOF: u16 = 0x000A;
    const CONTINUE: u16 = 0x003C;
    const FILEPASS: u16 = 0x002F;
    const OBJPROJ: u16 = 0x00D3;
    const BOUNDSHEET: u16 = 0x0085;
    const TABID: u16 = 0x013D;
    const SUPBOOK: u16 = 0x01AE;
    const EXTERNSHEET: u16 = 0x0017;
    const LBL: u16 = 0x0018;
    const WINDOW1: u16 = 0x003D;
    const EXTSST: u16 = 0x00FF;
    const INDEX: u16 = 0x020B;
    const DT_VB_MODULE: u8 = 0x06;
    const DT_MACRO_SHEET: u8 = 0x01;
    /// XTI itabFirst/itabLast value for a sheet that no longer exists.
    const DELETED_TAB: u16 = 0xFFFF;

    pub struct Stripped {
        pub bytes: Vec<u8>,
        pub removed: Vec<String>,
    }

    #[derive(Clone, Copy)]
    struct Rec {
        typ: u16,
        start: usize,
        len: usize,
    }
    impl Rec {
        fn end(&self) -> usize {
            self.start + 4 + self.len
        }
    }

    fn records(s: &[u8]) -> Result<(Vec<Rec>, usize)> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 4 <= s.len() {
            let typ = u16::from_le_bytes([s[pos], s[pos + 1]]);
            let len = u16::from_le_bytes([s[pos + 2], s[pos + 3]]) as usize;
            ensure!(pos + 4 + len <= s.len(), "record {typ:#06x} at {pos} runs past the stream");
            out.push(Rec { typ, start: pos, len });
            pos += 4 + len;
        }
        Ok((out, pos))
    }

    fn body<'a>(s: &'a [u8], r: &Rec) -> &'a [u8] {
        &s[r.start + 4..r.end()]
    }

    fn u16_at(d: &[u8], o: usize) -> Result<u16> {
        d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).context("record too short")
    }
    fn u32_at(d: &[u8], o: usize) -> Result<u32> {
        d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).context("record too short")
    }
    fn put_u16(d: &mut [u8], o: usize, v: u16) {
        d[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(d: &mut [u8], o: usize, v: u32) {
        d[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// ShortXLUnicodeString: cch u8, fHighByte u8, then 1- or 2-byte characters.
    fn sheet_name(d: &[u8]) -> String {
        let cch = d.get(6).copied().unwrap_or(0) as usize;
        let wide = d.get(7).is_some_and(|f| f & 1 == 1);
        let body = d.get(8..).unwrap_or(&[]);
        if wide {
            let units: Vec<u16> = body.as_chunks::<2>().0.iter().take(cch).map(|c| u16::from_le_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        } else {
            body.iter().take(cch).map(|&b| b as char).collect()
        }
    }

    struct Sheet {
        rec: usize,
        lb: usize,
        dt: u8,
        name: String,
    }

    pub fn strip(s: &[u8]) -> Result<Stripped> {
        let (recs, tail) = records(s)?;
        let data = |r: &Rec| body(s, r);
        let first = recs.first().context("empty Workbook stream")?;
        ensure!(first.typ == BOF && u16_at(data(first), 0)? == 0x0600, "not a BIFF8 workbook");
        ensure!(u16_at(data(first), 2)? == 0x0005, "stream does not start with the workbook globals");
        let globals_end = recs.iter().position(|r| r.typ == EOF).context("globals have no EOF")?;
        let globals = &recs[..=globals_end];
        ensure!(!globals.iter().any(|r| r.typ == FILEPASS), "workbook is encrypted");

        let index_at = |pos: usize| recs.binary_search_by_key(&pos, |r| r.start).ok();
        let mut sheets = Vec::new();
        for (i, r) in globals.iter().enumerate().filter(|(_, r)| r.typ == BOUNDSHEET) {
            let d = data(r);
            sheets.push(Sheet { rec: i, lb: u32_at(d, 0)? as usize, dt: *d.get(5).context("short BoundSheet8")?, name: sheet_name(d) });
        }

        // What goes: record indices and whole substreams.
        let mut gone = vec![false; recs.len()];
        let mut removed = Vec::new();
        for (i, _) in globals.iter().enumerate().filter(|(_, r)| r.typ == OBJPROJ) {
            gone[i] = true;
            removed.push("OBJPROJ record (VBA project marker)".to_string());
        }
        let mut sheet_gone = vec![false; sheets.len()];
        for (k, sh) in sheets.iter().enumerate().filter(|(_, sh)| sh.dt == DT_VB_MODULE) {
            let bof = index_at(sh.lb).with_context(|| format!("module sheet {} has no record at its offset", sh.name))?;
            ensure!(recs[bof].typ == BOF && u16_at(data(&recs[bof]), 2)? == 0x0006, "module sheet {} does not start with a module BOF", sh.name);
            let mut depth = 0usize;
            let mut end = None;
            for (j, r) in recs.iter().enumerate().skip(bof) {
                match r.typ {
                    BOF => depth += 1,
                    EOF => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(j);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let end = end.with_context(|| format!("module sheet {} has no EOF", sh.name))?;
            gone[bof..=end].iter_mut().for_each(|g| *g = true);
            gone[sh.rec] = true;
            sheet_gone[k] = true;
            removed.push(format!("module sheet {}", sh.name));
        }
        if !gone.iter().any(|g| *g) {
            return Ok(Stripped { bytes: s.to_vec(), removed });
        }

        // Sheet index remap (old index → new index; None for removed sheets).
        let n_old = sheets.len();
        let mut remap = Vec::with_capacity(n_old);
        let mut next = 0u16;
        for g in &sheet_gone {
            remap.push(if *g { None } else { Some(next) });
            if !*g {
                next = next.checked_add(1).context("more than 65,535 sheets")?;
            }
        }
        let n_new = next;
        let any_sheet_gone = sheet_gone.iter().any(|g| *g);
        let map_tab = |i: u16| -> Result<u16> {
            match remap.get(i as usize) {
                Some(Some(n)) => Ok(*n),
                Some(None) => bail!("a reference targets the module sheet itself"),
                None => bail!("sheet index {i} out of range"),
            }
        };
        // For a range bound that lands on a removed sheet, move inward to the nearest kept one.
        let map_bound = |i: u16, forward: bool| -> Result<u16> {
            let mut j = i as i64;
            while j >= 0 && (j as usize) < n_old {
                if let Some(n) = remap[j as usize] {
                    return Ok(n);
                }
                j += if forward { 1 } else { -1 };
            }
            bail!("no kept sheet near index {i}")
        };

        // Phase A: data rewrites that may change a record's length (sheet indices).
        let mut patched: Vec<Option<Vec<u8>>> = vec![None; recs.len()];
        let mut supbook_no = 0u16;
        let mut dangling = 0usize;
        let mut self_supbooks = Vec::new();
        for (i, r) in globals.iter().enumerate() {
            if gone[i] || !any_sheet_gone {
                continue;
            }
            let d = data(r);
            let followed_by_continue = recs.get(i + 1).is_some_and(|n| n.typ == CONTINUE);
            match r.typ {
                TABID => {
                    ensure!(d.len() == 2 * n_old, "TabId does not list one id per sheet");
                    let kept: Vec<u8> = d.as_chunks::<2>().0.iter().zip(&sheet_gone).filter(|(_, g)| !**g).flat_map(|(c, _)| c.to_vec()).collect();
                    patched[i] = Some(kept);
                }
                SUPBOOK => {
                    if d.len() == 4 && u16_at(d, 2)? == 0x0401 {
                        ensure!(u16_at(d, 0)? as usize == n_old, "self-reference SupBook sheet count differs");
                        let mut nd = d.to_vec();
                        put_u16(&mut nd, 0, n_new);
                        patched[i] = Some(nd);
                        self_supbooks.push(supbook_no);
                    }
                    supbook_no += 1;
                }
                EXTERNSHEET => {
                    ensure!(!followed_by_continue, "ExternSheet continues in a CONTINUE record");
                    let n = u16_at(d, 0)? as usize;
                    ensure!(d.len() == 2 + 6 * n, "ExternSheet length does not match its count");
                    let mut nd = d.to_vec();
                    for x in 0..n {
                        let o = 2 + 6 * x;
                        if !self_supbooks.contains(&u16_at(d, o)?) {
                            continue;
                        }
                        let (first, last) = (u16_at(d, o + 2)?, u16_at(d, o + 4)?);
                        // 0xFFFE / 0xFFFF are workbook-level / invalid markers, not sheets.
                        if first >= 0xFFFE || last >= 0xFFFE {
                            continue;
                        }
                        ensure!(first <= last && (last as usize) < n_old, "ExternSheet sheet range out of bounds");
                        let tabs: Vec<u16> = (first..=last).filter_map(|t| remap[t as usize]).collect();
                        let (nf, nl) = match (tabs.first(), tabs.last()) {
                            (Some(f), Some(l)) => (*f, *l),
                            // Only the module sheet: mark it as a deleted sheet, as Excel does
                            // when a referenced sheet is deleted (formulas using it show #REF!).
                            _ => {
                                dangling += 1;
                                (DELETED_TAB, DELETED_TAB)
                            }
                        };
                        put_u16(&mut nd, o + 2, nf);
                        put_u16(&mut nd, o + 4, nl);
                    }
                    patched[i] = Some(nd);
                }
                LBL => {
                    let itab = u16_at(d, 8)?;
                    if itab != 0 {
                        let mut nd = d.to_vec();
                        put_u16(&mut nd, 8, map_tab(itab - 1)? + 1);
                        patched[i] = Some(nd);
                    }
                }
                WINDOW1 => {
                    let mut nd = d.to_vec();
                    let cur = u16_at(d, 10)?;
                    let first_tab = u16_at(d, 12)?;
                    let sel = u16_at(d, 14)?;
                    let fix = |t: u16| map_bound(t, true).or_else(|_| map_bound(t, false)).unwrap_or(0);
                    put_u16(&mut nd, 10, fix(cur));
                    put_u16(&mut nd, 12, fix(first_tab));
                    put_u16(&mut nd, 14, sel.clamp(1, n_new.max(1)));
                    patched[i] = Some(nd);
                }
                _ => {}
            }
        }

        if dangling > 0 {
            removed.push(format!("{dangling} ExternSheet reference(s) to the module sheet (now marked as a deleted sheet)"));
        }

        // Layout: new start of every kept record.
        let mut new_start = vec![usize::MAX; recs.len()];
        let mut pos = 0;
        for (i, r) in recs.iter().enumerate() {
            if gone[i] {
                continue;
            }
            new_start[i] = pos;
            pos += 4 + patched[i].as_ref().map_or(r.len, Vec::len);
        }
        let resized: Vec<bool> = recs.iter().zip(&patched).map(|(r, p)| p.as_ref().is_some_and(|p| p.len() != r.len)).collect();
        let map_off = |old: usize| -> Result<u32> {
            let i = match recs.binary_search_by_key(&old, |r| r.start) {
                Ok(i) => i,
                Err(0) => bail!("offset {old} before the first record"),
                Err(i) => i - 1,
            };
            let r = &recs[i];
            ensure!(old < r.end(), "offset {old} is past the stream");
            ensure!(!gone[i], "offset {old} points into removed bytes");
            let inner = old - r.start;
            ensure!(!resized[i] || inner < 4, "offset {old} inside a resized record");
            Ok((new_start[i] + inner) as u32)
        };

        // Phase B: absolute offsets (these records keep their length).
        for (i, r) in recs.iter().enumerate() {
            if gone[i] {
                continue;
            }
            let d = data(r);
            match r.typ {
                BOUNDSHEET if i <= globals_end => {
                    let mut nd = d.to_vec();
                    put_u32(&mut nd, 0, map_off(u32_at(d, 0)? as usize)?);
                    patched[i] = Some(nd);
                }
                EXTSST if i <= globals_end => {
                    ensure!(!recs.get(i + 1).is_some_and(|n| n.typ == CONTINUE), "ExtSST continues in a CONTINUE record");
                    ensure!(d.len() >= 2 && (d.len() - 2) % 8 == 0, "ExtSST length is not 2 + 8n");
                    let mut nd = d.to_vec();
                    for o in (2..d.len()).step_by(8) {
                        put_u32(&mut nd, o, map_off(u32_at(d, o)? as usize)?);
                    }
                    patched[i] = Some(nd);
                }
                INDEX => {
                    ensure!(d.len() >= 16 && d.len() % 4 == 0, "Index length is not 16 + 4n");
                    let mut nd = d.to_vec();
                    for o in (12..d.len()).step_by(4) {
                        let v = u32_at(d, o)?;
                        if v != 0 {
                            put_u32(&mut nd, o, map_off(v as usize)?);
                        }
                    }
                    patched[i] = Some(nd);
                }
                _ => {}
            }
        }

        let mut out = Vec::with_capacity(s.len());
        for (i, r) in recs.iter().enumerate() {
            if gone[i] {
                continue;
            }
            match &patched[i] {
                Some(d) => {
                    out.extend_from_slice(&r.typ.to_le_bytes());
                    out.extend_from_slice(&u16::try_from(d.len())?.to_le_bytes());
                    out.extend_from_slice(d);
                }
                None => out.extend_from_slice(&s[r.start..r.end()]),
            }
        }
        out.extend_from_slice(&s[tail..]);
        verify(&out, n_new as usize)?;
        Ok(Stripped { bytes: out, removed })
    }

    /// Excel 4.0 (XLM) macros a Workbook stream still carries once VBA is gone: macro sheets
    /// (BoundSheet8 dt = 0x01) and defined names Excel runs on open/close (Lbl built-in
    /// Auto_Open 0x01, Auto_Close 0x02, Auto_Activate 0x0A, Auto_Deactivate 0x0B, or a user name
    /// starting with Auto_Open/Auto_Close). An encrypted globals substream cannot be checked, so it
    /// is an error, as is a stream that does not parse.
    pub fn xlm_macros(s: &[u8]) -> Result<Vec<String>> {
        let (recs, _) = records(s)?;
        let first = recs.first().context("empty Workbook stream")?;
        ensure!(first.typ == BOF && u16_at(body(s, first), 0)? == 0x0600, "not a BIFF8 workbook");
        let globals_end = recs.iter().position(|r| r.typ == EOF).context("globals have no EOF")?;
        let mut out = Vec::new();
        for r in &recs[..=globals_end] {
            let d = body(s, r);
            match r.typ {
                FILEPASS => bail!("workbook is encrypted, so its sheets cannot be checked for Excel 4.0 macros"),
                BOUNDSHEET if d.get(5) == Some(&DT_MACRO_SHEET) => out.push(format!("Excel 4.0 macro sheet {}", sheet_name(d))),
                LBL => {
                    let grbit = u16_at(d, 0)?;
                    let cch = *d.get(3).context("short Lbl")? as usize;
                    let wide = d.get(14).is_some_and(|f| f & 1 == 1);
                    let chars = d.get(15..).unwrap_or(&[]);
                    if grbit & 0x0020 != 0 {
                        let code = chars.first().copied().unwrap_or(0xFF);
                        if matches!(code, 0x01 | 0x02 | 0x0A | 0x0B) {
                            out.push(format!("built-in name {} (runs a macro on open/close)", ["", "Auto_Open", "Auto_Close", "", "", "", "", "", "", "", "Auto_Activate", "Auto_Deactivate"][code as usize]));
                        }
                    } else {
                        let name: String = if wide {
                            let units: Vec<u16> = chars.as_chunks::<2>().0.iter().take(cch).map(|c| u16::from_le_bytes(*c)).collect();
                            String::from_utf16_lossy(&units)
                        } else {
                            chars.iter().take(cch).map(|&b| b as char).collect()
                        };
                        if crate::extract::opc::is_auto_run_name(&name) {
                            out.push(format!("defined name {name} (runs a macro on open/close)"));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// The rewritten stream parses, has the expected sheet count, and every BoundSheet8 points at
    /// a BOF.
    fn verify(s: &[u8], sheets: usize) -> Result<()> {
        let (recs, _) = records(s)?;
        let globals_end = recs.iter().position(|r| r.typ == EOF).context("globals have no EOF")?;
        let bounds: Vec<&Rec> = recs[..globals_end].iter().filter(|r| r.typ == BOUNDSHEET).collect();
        ensure!(bounds.len() == sheets, "sheet count changed unexpectedly");
        for b in bounds {
            let lb = u32_at(&s[b.start + 4..b.end()], 0)? as usize;
            let ok = recs.binary_search_by_key(&lb, |r| r.start).is_ok_and(|i| recs[i].typ == BOF);
            ensure!(ok, "a sheet offset does not land on a BOF after rewriting");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zip::write::SimpleFileOptions;

    use crate::extract::tests::{vba_project_bin, write_vba, zip_of, WORM};

    fn assert_no_vba(bytes: &[u8]) {
        let f = extract::facts(bytes);
        assert!(f.vba.is_empty(), "VBA left: {:?}", f.vba.iter().map(|m| &m.name).collect::<Vec<_>>());
        assert!(!f.vba_unreadable);
    }

    // ---- OOXML ----

    const XL_MAIN_MACRO: &str = "application/vnd.ms-excel.sheet.macroEnabled.main+xml";
    const XL_MAIN_PLAIN: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";

    fn xlsm() -> Vec<u8> {
        let parts: Vec<(&str, Vec<u8>)> = vec![
            (
                "[Content_Types].xml",
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="{XL_MAIN_MACRO}"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/vbaProjectSignature.bin" ContentType="application/vnd.ms-office.vbaProjectSignature"/></Types>"#
                )
                .into_bytes(),
            ),
            (
                "_rels/.rels",
                br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#
                    .to_vec(),
            ),
            (
                "xl/workbook.xml",
                br#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><workbookPr codeName="ThisWorkbook"/><sheets><sheet name="Data" sheetId="1" r:id="rId1"/></sheets></workbook>"#.to_vec(),
            ),
            (
                "xl/_rels/workbook.xml.rels",
                br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>"#
                    .to_vec(),
            ),
            ("xl/worksheets/sheet1.xml", br#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>81 dong</t></is></c></row></sheetData></worksheet>"#.to_vec()),
            ("xl/vbaProject.bin", vba_project_bin()),
            (
                "xl/_rels/vbaProject.bin.rels",
                br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProjectSignature" Target="vbaProjectSignature.bin"/></Relationships>"#.to_vec(),
            ),
            ("xl/vbaProjectSignature.bin", vec![0x30, 0x82, 0x01, 0x00]),
        ];
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in parts {
            w.start_file(name, SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated)).unwrap();
            w.write_all(&data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn unzip(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let mut ar = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        (0..ar.len())
            .map(|i| {
                let mut f = ar.by_index(i).unwrap();
                let mut v = Vec::new();
                f.read_to_end(&mut v).unwrap();
                (f.name().to_string(), v)
            })
            .collect()
    }

    #[test]
    fn xlsm_becomes_macro_free_xlsx() {
        let input = xlsm();
        assert_eq!(extract::facts(&input).vba.len(), 1, "fixture carries one module");
        let out = clean(&input).unwrap();
        assert_no_vba(&out.bytes);
        assert_eq!(out.new_extension, Some("xlsx"));

        let a = unzip(&input);
        let b = unzip(&out.bytes);
        let gone: Vec<&str> = a.keys().filter(|k| !b.contains_key(*k)).map(String::as_str).collect();
        assert_eq!(gone, ["xl/_rels/vbaProject.bin.rels", "xl/vbaProject.bin", "xl/vbaProjectSignature.bin"]);
        for name in ["_rels/.rels", "xl/workbook.xml", "xl/worksheets/sheet1.xml"] {
            assert_eq!(a[name], b[name], "{name} must be byte-identical");
        }
        let rels = String::from_utf8(b["xl/_rels/workbook.xml.rels"].clone()).unwrap();
        assert!(rels.contains("worksheets/sheet1.xml") && !rels.contains("vbaProject"), "{rels}");
        let ct = String::from_utf8(b["[Content_Types].xml"].clone()).unwrap();
        assert!(ct.contains(XL_MAIN_PLAIN) && !ct.contains("macroEnabled") && !ct.contains("vbaProject"), "{ct}");
        assert!(ct.contains("worksheet+xml"));
        assert!(out.removed.iter().any(|r| r.starts_with("VBA project xl/vbaProject.bin") && r.contains("Kangatang")), "{:?}", out.removed);
    }

    #[test]
    fn docm_drops_vba_data_and_switches_type() {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default();
        let files: Vec<(&str, Vec<u8>)> = vec![
            ("[Content_Types].xml", br#"<Types><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/><Override PartName="/word/vbaData.xml" ContentType="application/vnd.ms-word.vbaData+xml"/></Types>"#.to_vec()),
            ("word/document.xml", b"<w:document/>".to_vec()),
            ("word/_rels/document.xml.rels", br#"<Relationships><Relationship Id="rId9" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="/word/vbaProject.bin"></Relationship></Relationships>"#.to_vec()),
            ("word/vbaProject.bin", vba_project_bin()),
            ("word/_rels/vbaProject.bin.rels", br#"<Relationships><Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/wordVbaData" Target="vbaData.xml"/></Relationships>"#.to_vec()),
            ("word/vbaData.xml", b"<wne:vbaSuppData/>".to_vec()),
        ];
        for (n, d) in files {
            w.start_file(n, opts).unwrap();
            w.write_all(&d).unwrap();
        }
        let input = w.finish().unwrap().into_inner();
        let out = clean(&input).unwrap();
        assert_no_vba(&out.bytes);
        assert_eq!(out.new_extension, Some("docx"));
        let b = unzip(&out.bytes);
        assert_eq!(b.keys().collect::<Vec<_>>(), ["[Content_Types].xml", "word/_rels/document.xml.rels", "word/document.xml"]);
        assert_eq!(b["word/document.xml"], b"<w:document/>");
        assert_eq!(b["word/_rels/document.xml.rels"], b"<Relationships></Relationships>");
        let ct = String::from_utf8(b["[Content_Types].xml"].clone()).unwrap();
        assert!(!ct.contains("vba") && ct.contains("wordprocessingml.document.main+xml"), "{ct}");
    }

    // ---- OLE2 / BIFF8 ----

    fn rec(t: u16, d: &[u8]) -> Vec<u8> {
        let mut v = t.to_le_bytes().to_vec();
        v.extend_from_slice(&(d.len() as u16).to_le_bytes());
        v.extend_from_slice(d);
        v
    }

    fn bof(dt: u16) -> Vec<u8> {
        let mut d = vec![0x00, 0x06];
        d.extend_from_slice(&dt.to_le_bytes());
        d.extend_from_slice(&[0x54, 0x38, 0xCD, 0x07, 0xC9, 0x00, 0x02, 0x00, 0x06, 0x08, 0x00, 0x00]);
        d
    }

    fn boundsheet(lb: u32, dt: u8, name: &str) -> Vec<u8> {
        let mut d = lb.to_le_bytes().to_vec();
        d.extend_from_slice(&[0, dt, name.len() as u8, 0]);
        d.extend_from_slice(name.as_bytes());
        d
    }

    /// A BIFF8 Workbook stream with every record whose offsets or sheet indices the cleaner
    /// rewrites. With `module`, it also has OBJPROJ and a "Visual Basic module" sheet in front of
    /// the data sheet, the way the Kangatang sample is laid out. Built independently of the
    /// cleaner: `biff(false)` is what cleaning `biff(true)` must produce.
    fn biff(module: bool) -> Vec<u8> {
        let n: u16 = if module { 2 } else { 1 };
        let data_tab = n - 1;
        let mut s = rec(0x0809, &bof(0x0005));
        if module {
            s.extend(rec(0x00D3, &[]));
        }
        s.extend(rec(0x01BA, b"\x0c\x00\x00ThisWorkbook"));
        s.extend(rec(0x013D, if module { &[2, 0, 1, 0] } else { &[1, 0] }));
        let mut w1 = vec![0u8; 10];
        w1.extend_from_slice(&data_tab.to_le_bytes());
        w1.extend_from_slice(&data_tab.to_le_bytes());
        w1.extend_from_slice(&1u16.to_le_bytes());
        w1.extend_from_slice(&600u16.to_le_bytes());
        s.extend(rec(0x003D, &w1));
        let bs_module = s.len();
        if module {
            s.extend(rec(0x0085, &boundsheet(0, 6, "Kangatang")));
        }
        let bs_data = s.len();
        s.extend(rec(0x0085, &boundsheet(0, 0, "Data")));
        s.extend(rec(0x01AE, &[n as u8, 0, 0x01, 0x04]));
        // Two XTIs: the data sheet, and (as in the real sample) one that covers only the module
        // sheet, which cleaning turns into the "deleted sheet" marker 0xFFFF.
        let mut xti = vec![2, 0, 0, 0];
        xti.extend_from_slice(&data_tab.to_le_bytes());
        xti.extend_from_slice(&data_tab.to_le_bytes());
        xti.extend_from_slice(&[0, 0]);
        xti.extend_from_slice(if module { &[0, 0, 0, 0] } else { &[0xFF, 0xFF, 0xFF, 0xFF] });
        s.extend(rec(0x0017, &xti));
        let mut lbl = vec![0, 0, 0, 1, 0, 0, 0, 0];
        lbl.extend_from_slice(&(data_tab + 1).to_le_bytes());
        lbl.extend_from_slice(&[0, 0, 0, 0, 0, b'X']);
        s.extend(rec(0x0018, &lbl));
        let sst = s.len();
        s.extend(rec(0x00FC, &[1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, b'h', b'i']));
        let mut ext = 8u16.to_le_bytes().to_vec();
        ext.extend_from_slice(&((sst + 12) as u32).to_le_bytes());
        ext.extend_from_slice(&[12, 0, 0, 0]);
        s.extend(rec(0x00FF, &ext));
        s.extend(rec(0x000A, &[]));
        if module {
            let lb = s.len() as u32;
            s[bs_module + 4..bs_module + 8].copy_from_slice(&lb.to_le_bytes());
            s.extend(rec(0x0809, &bof(0x0006)));
            s.extend(rec(0x0083, &[0, 0]));
            s.extend(rec(0x000A, &[]));
        }
        let lb = s.len() as u32;
        s[bs_data + 4..bs_data + 8].copy_from_slice(&lb.to_le_bytes());
        s.extend(rec(0x0809, &bof(0x0010)));
        let index = s.len();
        s.extend(rec(0x020B, &[0u8; 20]));
        let defcol = s.len();
        s.extend(rec(0x0055, &[8, 0]));
        let row = s.len();
        s.extend(rec(0x0208, &[0u8; 16]));
        let dbcell = s.len();
        s.extend(rec(0x00D7, &((dbcell - row) as u32).to_le_bytes()));
        s.extend(rec(0x000A, &[]));
        let mut idx = vec![0u8; 8];
        idx.extend_from_slice(&1u32.to_le_bytes());
        idx.extend_from_slice(&(defcol as u32).to_le_bytes());
        idx.extend_from_slice(&(dbcell as u32).to_le_bytes());
        s[index + 4..index + 24].copy_from_slice(&idx);
        s
    }

    fn ole_file(workbook: &[u8]) -> Vec<u8> {
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        comp.create_stream("/Workbook").unwrap().write_all(workbook).unwrap();
        comp.create_stream("/\u{5}SummaryInformation").unwrap().write_all(&[0xFE, 0xFF, 0, 0, 1, 2, 3]).unwrap();
        write_vba(&mut comp, "/_VBA_PROJECT_CUR", &[("Kangatang", WORM), ("ThisWorkbook", "Attribute VB_Name = \"ThisWorkbook\"\r\n")]);
        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

    fn streams(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let mut comp = cfb::CompoundFile::open(Cursor::new(bytes)).unwrap();
        let paths: Vec<PathBuf> = comp.walk().filter(|e| e.is_stream()).map(|e| e.path().to_path_buf()).collect();
        paths
            .into_iter()
            .map(|p| {
                let mut v = Vec::new();
                comp.open_stream(&p).unwrap().read_to_end(&mut v).unwrap();
                (p.display().to_string(), v)
            })
            .collect()
    }

    #[test]
    fn xls_vba_storage_removed_other_streams_identical() {
        let input = ole_file(&biff(false));
        assert_eq!(extract::facts(&input).vba.len(), 2);
        let out = clean(&input).unwrap();
        assert_no_vba(&out.bytes);
        assert_eq!(out.new_extension, None);
        let mut expected = streams(&input);
        expected.retain(|k, _| !k.starts_with("/_VBA_PROJECT_CUR"));
        assert_eq!(streams(&out.bytes), expected);
        assert!(out.removed[0].contains("_VBA_PROJECT_CUR") && out.removed[0].contains("Kangatang, ThisWorkbook"), "{:?}", out.removed);
        assert!(out.kept.is_empty(), "{:?}", out.kept);
    }

    #[test]
    fn xls_module_sheet_and_objproj_removed_offsets_recomputed() {
        let input = ole_file(&biff(true));
        let out = clean(&input).unwrap();
        assert_no_vba(&out.bytes);
        assert!(out.kept.is_empty(), "{:?}", out.kept);
        let got = streams(&out.bytes);
        assert_eq!(got["/Workbook"], biff(false), "Workbook must equal the one built without the module");
        assert_eq!(got["/\u{5}SummaryInformation"], streams(&input)["/\u{5}SummaryInformation"]);
        assert!(out.removed.contains(&"module sheet Kangatang".to_string()), "{:?}", out.removed);
        assert!(out.removed.iter().any(|r| r.starts_with("OBJPROJ")));
        assert!(out.removed.iter().any(|r| r.starts_with("1 ExternSheet reference")), "{:?}", out.removed);
    }

    #[test]
    fn xls_encrypted_workbook_refused() {
        // Encrypted globals hide BoundSheet8 types and names, so macro sheets cannot be ruled out.
        let mut wb = biff(true);
        let bof_len = 4 + 16;
        let tail = wb.split_off(bof_len);
        wb.extend(rec(0x002F, &[0, 0]));
        wb.extend(tail);
        let err = clean(&ole_file(&wb)).unwrap_err();
        assert!(format!("{err:#}").contains("encrypted"), "{err:#}");
    }

    #[test]
    fn doc_macros_storage_removed() {
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        comp.create_stream("/WordDocument").unwrap().write_all(&[0xEC, 0xA5, 1, 2]).unwrap();
        comp.create_stream("/1Table").unwrap().write_all(&[9; 600]).unwrap();
        write_vba(&mut comp, "/Macros", &[("NewMacros", "Sub AutoOpen()\r\nShell \"x\"\r\nEnd Sub\r\n")]);
        comp.flush().unwrap();
        let input = comp.into_inner().into_inner();
        let out = clean(&input).unwrap();
        assert_no_vba(&out.bytes);
        let mut expected = streams(&input);
        expected.retain(|k, _| !k.starts_with("/Macros"));
        assert_eq!(streams(&out.bytes), expected);
    }

    #[test]
    fn rejects_oversized_and_non_office_input() {
        assert!(check_size(MAX_INPUT).is_ok());
        assert!(check_size(MAX_INPUT + 1).is_err());
        assert!(clean(b"plain text").is_err());
    }

    // ---- review fixes: regression tests ----

    const NS_CT: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
    const NS_RELS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
    const REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    const VBA_REL: &str = "http://schemas.microsoft.com/office/2006/relationships/vbaProject";

    fn root_rels(main: &str) -> Vec<u8> {
        format!(r#"<Relationships xmlns="{NS_RELS}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="{main}"/></Relationships>"#).into_bytes()
    }

    /// A small workbook package: `ct_extra` goes inside `<Types>`, `wb_rels` is the whole
    /// workbook.xml.rels, `extra` are more parts.
    fn package(ct_name: &str, main_type: &str, ct_extra: &str, wb_rels: &str, workbook: &str, extra: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let ct = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="{NS_CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="{main_type}"/>{ct_extra}</Types>"#
        );
        let mut parts: Vec<(&str, Vec<u8>)> = vec![
            (ct_name, ct.into_bytes()),
            ("_rels/.rels", root_rels("xl/workbook.xml")),
            ("xl/workbook.xml", workbook.as_bytes().to_vec()),
            ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes().to_vec()),
            ("xl/worksheets/sheet1.xml", b"<worksheet><sheetData/></worksheet>".to_vec()),
        ];
        parts.extend(extra.iter().cloned());
        let refs: Vec<(&str, &[u8])> = parts.iter().map(|(n, d)| (*n, d.as_slice())).collect();
        zip_of(&refs)
    }

    const WORKBOOK: &str = r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Data" sheetId="1"/></sheets></workbook>"#;

    fn wb_rels(more: &str) -> String {
        format!(r#"<Relationships xmlns="{NS_RELS}"><Relationship Id="rId1" Type="{REL}/worksheet" Target="worksheets/sheet1.xml"/>{more}</Relationships>"#)
    }

    fn ok_xlsx(input: &[u8]) -> (Cleaned, BTreeMap<String, Vec<u8>>) {
        assert!(!extract::facts(input).vba.is_empty(), "fixture must carry VBA the scanner sees");
        let out = clean(input).unwrap();
        assert_no_vba(&out.bytes);
        assert_eq!(out.new_extension, Some("xlsx"));
        let files = unzip(&out.bytes);
        (out, files)
    }

    #[test]
    fn renamed_vba_behind_char_reference_type_is_removed() {
        let rels = wb_rels(&format!(r#"<Relationship Id="rId2" Type="{}&#116;" Target="data.bin"/>"#, &VBA_REL[..VBA_REL.len() - 1]));
        let input = package("[Content_Types].xml", XL_MAIN_MACRO, "", &rels, WORKBOOK, &[("xl/data.bin", vba_project_bin())]);
        let (out, files) = ok_xlsx(&input);
        assert!(!files.contains_key("xl/data.bin"));
        let rels = String::from_utf8(files["xl/_rels/workbook.xml.rels"].clone()).unwrap();
        assert!(rels.contains("rId1") && !rels.contains("rId2"), "{rels}");
        assert!(out.removed.iter().any(|r| r.starts_with("VBA project xl/data.bin") && r.contains("Kangatang")), "{:?}", out.removed);
    }

    #[test]
    fn prefixed_relationship_element_is_removed() {
        let rels = format!(
            r#"<r:Relationships xmlns:r="{NS_RELS}"><r:Relationship Id="rId1" Type="{REL}/worksheet" Target="worksheets/sheet1.xml"/><r:Relationship Id="rId2" Type="{VBA_REL}" Target="/xl/data.bin"/></r:Relationships>"#
        );
        let input = package("[Content_Types].xml", XL_MAIN_MACRO, "", &rels, WORKBOOK, &[("xl/data.bin", vba_project_bin())]);
        let (_, files) = ok_xlsx(&input);
        assert!(!files.contains_key("xl/data.bin"));
        let rels = String::from_utf8(files["xl/_rels/workbook.xml.rels"].clone()).unwrap();
        assert!(rels.starts_with("<r:Relationships") && rels.contains("rId1") && !rels.contains("rId2"), "{rels}");
    }

    #[test]
    fn vba_found_by_content_type_override_and_default() {
        let ct = r#"<Override PartName="/xl/media/image1.png" ContentType="application/vnd.ms-office.vbaProject"/><Default Extension="dat" ContentType="application/vnd.ms-office.vbaProject"/>"#;
        let input = package(
            "[Content_Types].xml",
            XL_MAIN_MACRO,
            ct,
            &wb_rels(""),
            WORKBOOK,
            &[("xl/media/image1.png", vba_project_bin()), ("xl/stuff.dat", vba_project_bin())],
        );
        let (_, files) = ok_xlsx(&input);
        assert!(!files.contains_key("xl/media/image1.png") && !files.contains_key("xl/stuff.dat"));
        let ct = String::from_utf8(files["[Content_Types].xml"].clone()).unwrap();
        assert!(!ct.to_ascii_lowercase().contains("vbaproject") && ct.contains(XL_MAIN_PLAIN), "{ct}");
    }

    #[test]
    fn unreferenced_ole_member_with_vba_is_removed() {
        let input = package("[Content_Types].xml", XL_MAIN_PLAIN, "", &wb_rels(""), WORKBOOK, &[("xl/blob", vba_project_bin())]);
        let (out, files) = ok_xlsx(&input);
        assert!(!files.contains_key("xl/blob"), "{:?}", out.removed);
    }

    #[test]
    fn lowercase_content_types_part_is_handled() {
        let rels = wb_rels(&format!(r#"<Relationship Id="rId2" Type="{VBA_REL}" Target="vbaProject.bin"/>"#));
        let input = package("[content_types].xml", XL_MAIN_MACRO, "", &rels, WORKBOOK, &[("xl/vbaProject.bin", vba_project_bin())]);
        let (_, files) = ok_xlsx(&input);
        let ct = String::from_utf8(files["[content_types].xml"].clone()).unwrap();
        assert!(ct.contains(XL_MAIN_PLAIN) && !ct.contains("macroEnabled"), "{ct}");
    }

    #[test]
    fn excel4_macro_sheets_are_refused() {
        let ct = r#"<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>"#;
        let input = package("[Content_Types].xml", XL_MAIN_MACRO, ct, &wb_rels(""), WORKBOOK, &[("xl/macrosheets/sheet1.xml", b"<xm:macrosheet/>".to_vec())]);
        let err = clean(&input).unwrap_err();
        assert!(format!("{err:#}").contains("Excel 4.0 macro sheet"), "{err:#}");
    }

    #[test]
    fn auto_open_defined_name_is_refused() {
        let wb = r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><definedNames><definedName name="_xlnm.Auto_Open">Data!$A$1</definedName></definedNames></workbook>"#;
        let err = clean(&package("[Content_Types].xml", XL_MAIN_PLAIN, "", &wb_rels(""), wb, &[])).unwrap_err();
        assert!(format!("{err:#}").contains("Auto_Open"), "{err:#}");
    }

    #[test]
    fn macro_enabled_addin_is_refused() {
        let err = clean(&package("[Content_Types].xml", "application/vnd.ms-excel.addin.macroEnabled.main+xml", "", &wb_rels(""), WORKBOOK, &[])).unwrap_err();
        assert!(format!("{err:#}").contains("macro-enabled"), "{err:#}");
    }

    #[test]
    fn remote_attached_template_is_removed() {
        let w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
        let ct = format!(
            r#"<Types xmlns="{NS_CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/><Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/></Types>"#
        );
        let settings = format!(r#"<w:settings xmlns:w="{w}" xmlns:r="{REL}"><w:zoom w:percent="100"/><w:attachedTemplate r:id="rId1"/></w:settings>"#);
        let settings_rels = format!(
            r#"<Relationships xmlns="{NS_RELS}"><Relationship Id="rId1" Type="{REL}/attachedTemplate" Target="http://203.0.113.9/t.dotm" TargetMode="External"/></Relationships>"#
        );
        let doc_rels = format!(r#"<Relationships xmlns="{NS_RELS}"><Relationship Id="rId1" Type="{REL}/settings" Target="settings.xml"/></Relationships>"#);
        let input = zip_of(&[
            ("[Content_Types].xml", ct.as_bytes()),
            ("_rels/.rels", &root_rels("word/document.xml")),
            ("word/document.xml", format!(r#"<w:document xmlns:w="{w}"/>"#).as_bytes()),
            ("word/_rels/document.xml.rels", doc_rels.as_bytes()),
            ("word/settings.xml", settings.as_bytes()),
            ("word/_rels/settings.xml.rels", settings_rels.as_bytes()),
        ]);
        assert!(!ooxml::macro_problems(&input).unwrap().is_empty());
        let out = clean(&input).unwrap();
        assert_eq!(out.new_extension, Some("docx"));
        let files = unzip(&out.bytes);
        let s = String::from_utf8(files["word/settings.xml"].clone()).unwrap();
        assert!(!s.contains("attachedTemplate") && s.contains("w:zoom"), "{s}");
        let r = String::from_utf8(files["word/_rels/settings.xml.rels"].clone()).unwrap();
        assert!(!r.contains("203.0.113.9"), "{r}");
        assert!(out.removed.iter().any(|r| r.contains("template injection")), "{:?}", out.removed);
        assert!(ooxml::macro_problems(&out.bytes).unwrap().is_empty());
    }

    #[test]
    fn embedded_ole_object_with_vba_is_cleaned_in_place() {
        let embedded = ole_file(&biff(true));
        let ct = r#"<Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.oleObject"/>"#;
        let input = package("[Content_Types].xml", XL_MAIN_PLAIN, ct, &wb_rels(""), WORKBOOK, &[("xl/embeddings/oleObject1.bin", embedded)]);
        let (out, files) = ok_xlsx(&input);
        let obj = &files["xl/embeddings/oleObject1.bin"];
        assert_no_vba(obj);
        assert_eq!(streams(obj)["/Workbook"], biff(false));
        assert!(out.removed.iter().any(|r| r.contains("inside embedded object xl/embeddings/oleObject1.bin")), "{:?}", out.removed);
    }

    #[test]
    fn embedded_package_with_vba_is_refused() {
        let input = package("[Content_Types].xml", XL_MAIN_PLAIN, "", &wb_rels(""), WORKBOOK, &[("xl/embeddings/Book1.xlsm", xlsm())]);
        let err = clean(&input).unwrap_err();
        assert!(format!("{err:#}").contains("embedded package"), "{err:#}");
    }

    #[test]
    fn nested_content_type_entries_do_not_panic() {
        // Overlapping element spans broke the old byte-cutting rewrite ("byte range starts at 151
        // but ends at 63"). Re-serialising has no spans; nested entries are just elements.
        for ct in [
            r#"<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Override>"#,
            r#"<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"><Override PartName="/xl/vbaProject.bin" ContentType="x"></Override></Default>"#,
            r#"<Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"><Override PartName="/xl/vbaProject.bin" ContentType="x"/></Override>"#,
        ] {
            let input = package("[Content_Types].xml", XL_MAIN_MACRO, ct, &wb_rels(""), WORKBOOK, &[("xl/vbaProject.bin", vba_project_bin())]);
            if let Ok(out) = clean(&input) {
                assert_no_vba(&out.bytes);
            }
        }
    }

    fn timed<T>(f: impl FnOnce() -> T) -> (T, std::time::Duration) {
        let t = std::time::Instant::now();
        let r = f();
        (r, t.elapsed())
    }

    /// Wall-clock limit: release is what ships; debug builds are ~20× slower.
    fn limit() -> std::time::Duration {
        std::time::Duration::from_millis(if cfg!(debug_assertions) { 15_000 } else { 1_000 })
    }

    #[test]
    fn huge_rels_part_is_linear() {
        // ~4 MB of unclosed `<Relationship Id="a">`: the old scan was quadratic (1 MB ≈ 20 s).
        let open = format!("<Relationships xmlns=\"{NS_RELS}\">{}", "<Relationship Id=\"a\">".repeat(200_000));
        let input = package("[Content_Types].xml", XL_MAIN_PLAIN, "", &open, WORKBOOK, &[]);
        let (r, took) = timed(|| clean(&input));
        eprintln!("unclosed rels: {took:?}");
        assert!(r.is_err() && took < limit(), "{took:?}");
        // ~6 MB of well-formed relationships: cleaned, still linear.
        let many = wb_rels(&format!(r#"<Relationship Id="x" Type="{REL}/hyperlink" Target="http://example.com/" TargetMode="External"/>"#).repeat(60_000));
        let input = package("[Content_Types].xml", XL_MAIN_PLAIN, "", &many, WORKBOOK, &[]);
        let (r, took) = timed(|| clean(&input));
        eprintln!("well-formed rels ({} bytes): {took:?}", many.len());
        assert!(r.is_ok() && took < limit(), "{took:?} {:?}", r.err());
    }

    #[test]
    fn decompression_budget_is_enforced_not_truncated() {
        // Three 1 MB rels parts against a 2 MB budget: an error, never a silently cut part.
        let big = wb_rels(&" ".repeat(1024 * 1024));
        let extra: Vec<(&str, Vec<u8>)> = vec![("xl/_rels/a.xml.rels", big.clone().into_bytes()), ("xl/_rels/b.xml.rels", big.clone().into_bytes())];
        let input = package("[Content_Types].xml", XL_MAIN_PLAIN, "", &big, WORKBOOK, &extra);
        assert!(input.len() < 64 * 1024);
        let err = ooxml::clean_with_budget(&input, 2 * 1024 * 1024).unwrap_err();
        assert!(format!("{err:#}").contains("budget"), "{err:#}");
        assert!(ooxml::clean_with_budget(&input, 8 * 1024 * 1024).is_ok());
    }

    #[test]
    fn overlapping_zip_entries_are_refused() {
        let input = package("[Content_Types].xml", XL_MAIN_PLAIN, "", &wb_rels(""), WORKBOOK, &[]);
        let cd: Vec<usize> = memchr::memmem::find_iter(&input, b"PK\x01\x02").collect();
        let mut bad = input.clone();
        let first = input[cd[1] + 42..cd[1] + 46].to_vec();
        bad[cd[2] + 42..cd[2] + 46].copy_from_slice(&first);
        let err = clean(&bad).unwrap_err();
        assert!(format!("{err:#}").contains("overlap"), "{err:#}");
    }

    #[test]
    fn xls_excel4_macro_sheet_is_refused() {
        let mut wb = biff(false);
        // Another BoundSheet8, dt = 0x01 (macro sheet), right before the globals EOF.
        let globals_eof = (0..wb.len()).rev().find(|&i| wb[i..].starts_with(&[0x0A, 0x00, 0x00, 0x00]) && i < 200).unwrap();
        let tail = wb.split_off(globals_eof);
        wb.extend(rec(0x0085, &boundsheet(0, 1, "Macro1")));
        wb.extend(tail);
        let err = clean(&ole_file(&wb)).unwrap_err();
        assert!(format!("{err:#}").contains("Excel 4.0 macro sheet Macro1"), "{err:#}");
    }

    #[test]
    fn xls_auto_open_name_is_refused() {
        let mut wb = biff(false);
        let globals_eof = (0..wb.len()).rev().find(|&i| wb[i..].starts_with(&[0x0A, 0x00, 0x00, 0x00]) && i < 200).unwrap();
        let tail = wb.split_off(globals_eof);
        // Lbl: fBuiltin, cch 1, built-in code 0x01 = Auto_Open.
        wb.extend(rec(0x0018, &[0x20, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]));
        wb.extend(tail);
        let err = clean(&ole_file(&wb)).unwrap_err();
        assert!(format!("{err:#}").contains("Auto_Open"), "{err:#}");
        assert!(biff::xlm_macros(&biff(false)).unwrap().is_empty());
    }

    #[test]
    fn more_than_65535_sheets_is_an_error_not_a_wrap() {
        let mut s = rec(0x0809, &bof(0x0005));
        for _ in 0..65_536 {
            s.extend(rec(0x0085, &boundsheet(0, 0, "S")));
        }
        let module_bs = s.len();
        s.extend(rec(0x0085, &boundsheet(0, 6, "M")));
        s.extend(rec(0x000A, &[]));
        let lb = s.len() as u32;
        s[module_bs + 4..module_bs + 8].copy_from_slice(&lb.to_le_bytes());
        s.extend(rec(0x0809, &bof(0x0006)));
        s.extend(rec(0x000A, &[]));
        let err = biff::strip(&s).err().expect("must not succeed");
        assert!(format!("{err:#}").contains("65,535"), "{err:#}");
    }

    fn stored(parts: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in parts {
            w.start_file(*name, SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    /// Random byte mutations of the fixtures through `facts` and `clean`: no panic, each call
    /// well under 100 ms. `cargo test --release -- --ignored fuzz`; GENRA_FUZZ_N sets the count.
    #[test]
    #[ignore]
    fn fuzz_mutations_never_panic() {
        fn restored(z: &[u8]) -> Vec<u8> {
            let files = unzip(z);
            stored(&files.iter().map(|(n, d)| (n.as_str(), d.clone())).collect::<Vec<_>>())
        }
        let embedded = package("[Content_Types].xml", XL_MAIN_PLAIN, "", &wb_rels(""), WORKBOOK, &[("xl/embeddings/oleObject1.bin", ole_file(&biff(true)))]);
        let renamed = package(
            "[Content_Types].xml",
            XL_MAIN_MACRO,
            r#"<Default Extension="dat" ContentType="application/vnd.ms-office.vbaProject"/>"#,
            &wb_rels(&format!(r#"<r:Relationship xmlns:r="{NS_RELS}" Id="rId2" Type="{VBA_REL}" Target="data.bin"/>"#)),
            WORKBOOK,
            &[("xl/data.bin", vba_project_bin()), ("xl/x.dat", vba_project_bin())],
        );
        let fixtures: Vec<Vec<u8>> = vec![
            xlsm(),
            restored(&xlsm()),
            restored(&embedded),
            restored(&renamed),
            ole_file(&biff(true)),
            ole_file(&biff(false)),
            vba_project_bin(),
        ];
        let n: usize = std::env::var("GENRA_FUZZ_N").ok().and_then(|v| v.parse().ok()).unwrap_or(3000);
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let (mut panics, mut slowest, mut calls) = (0, std::time::Duration::ZERO, 0);
        for k in 0..n {
            let mut b = fixtures[k % fixtures.len()].clone();
            for _ in 0..1 + rnd() % 8 {
                let at = (rnd() as usize) % b.len();
                match rnd() % 4 {
                    0 => b[at] = rnd() as u8,
                    1 => b[at] ^= 1 << (rnd() % 8),
                    2 => b[at] = [0x00, 0xFF, 0x7F, 0x80, b'<', b'>', b'&', b'"'][(rnd() % 8) as usize],
                    _ => b.truncate(at.max(8)),
                }
            }
            for f in [0, 1] {
                let t = std::time::Instant::now();
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if f == 0 {
                        let _ = extract::facts(&b);
                    } else if let Ok(out) = clean(&b) {
                        assert_no_vba(&out.bytes);
                    }
                }));
                let took = t.elapsed();
                calls += 1;
                slowest = slowest.max(took);
                if r.is_err() {
                    panics += 1;
                    eprintln!("panic on mutation {k} (fixture {}, {})", k % fixtures.len(), if f == 0 { "facts" } else { "clean" });
                }
            }
        }
        eprintln!("fuzz: {n} mutations, {calls} calls, {panics} panics, slowest {slowest:?}");
        assert_eq!(panics, 0);
        assert!(slowest < std::time::Duration::from_millis(100), "slowest call {slowest:?}");
    }
}
