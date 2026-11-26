//! Writes a macro-free copy of an Office file, keeping its data and formatting. This is the engine
//! behind "Dọn sạch giúp tôi". It parses and rewrites containers only; it never runs anything and
//! never touches the original bytes it was given.
//!
//! - OOXML (.xlsm/.docm/.pptm, or a renamed .xlsx carrying macros): the zip is rebuilt without the
//!   VBA parts, their relationships and content-type overrides, and the main part switches to the
//!   plain (macro-free) content type. Every other part is copied raw, byte for byte.
//! - OLE2 (.xls, .doc): the compound file is rewritten without the VBA project storage
//!   (`_VBA_PROJECT_CUR`, `Macros`); every other stream is copied unchanged. In an .xls, the
//!   Workbook stream also loses its OBJPROJ marker and its "Visual Basic module" sheets (see
//!   [`biff`]); if anything there looks unusual the Workbook stream is copied unchanged instead.
//!
//! The result is checked with [`crate::extract::facts`]: if any VBA is still visible, `clean`
//! fails rather than hand back a file that only looks clean.

use crate::extract::{self, Kind};
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

/// Inputs above this are refused: Office documents worth cleaning are far smaller.
pub const MAX_INPUT: usize = 200 * 1024 * 1024;
/// Cap on a single XML part read from a zip, so a zip bomb cannot exhaust memory.
const XML_CAP: u64 = 64 * 1024 * 1024;

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
        if let Some(first) = out.removed.iter_mut().find(|r| r.starts_with("VBA project")) {
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
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipArchive, ZipWriter};

    const CONTENT_TYPES: &str = "[Content_Types].xml";
    const VBA_CONTENT_TYPE: &str = "application/vnd.ms-office.vbaProject";
    /// Macro-enabled main part content type → plain one, and the extension that goes with it.
    const MAIN_TYPES: &[(&str, &str, &str)] = &[
        (
            "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
            "xlsx",
        ),
        (
            "application/vnd.ms-excel.template.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
            "xltx",
        ),
        (
            "application/vnd.ms-word.document.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            "docx",
        ),
        (
            "application/vnd.ms-word.template.macroEnabledTemplate.main+xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
            "dotx",
        ),
        (
            "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
            "pptx",
        ),
        (
            "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml",
            "ppsx",
        ),
        (
            "application/vnd.ms-powerpoint.template.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml",
            "potx",
        ),
    ];

    pub fn clean(bytes: &[u8]) -> Result<Cleaned> {
        let mut ar = ZipArchive::new(Cursor::new(bytes)).context("reading zip")?;
        let names: Vec<String> = (0..ar.len())
            .map(|i| ar.by_index_raw(i).map(|f| f.name().to_string()))
            .collect::<Result<_, _>>()?;
        let mut removed = Vec::new();
        let mut kept = Vec::new();

        // Parts to drop: by name, and by relationship type (a renamed vbaProject.bin still counts).
        let mut doomed: HashSet<String> = names.iter().filter(|n| is_vba_name(n)).map(|n| n.to_ascii_lowercase()).collect();
        let mut rels_text = Vec::new();
        for (i, name) in names.iter().enumerate() {
            if is_rels(name) {
                let text = read_text(&mut ar, i)?;
                for rel in relationships(&text) {
                    if is_vba_rel_type(&rel.kind) && !rel.external {
                        doomed.insert(resolve(&source_dir(name), &rel.target));
                    }
                }
                rels_text.push((i, text));
            }
        }
        // A dropped part's own relationships go with it (vbaProject.bin.rels → vbaData.xml).
        for name in &names {
            if is_rels(name) && doomed.contains(&source_part(name)) {
                doomed.insert(name.to_ascii_lowercase());
            }
        }

        let mut out = ZipWriter::new(Cursor::new(Vec::new()));
        for i in 0..names.len() {
            let name = &names[i];
            let lower = name.to_ascii_lowercase();
            if doomed.contains(&lower) {
                removed.push(describe_part(name));
                continue;
            }
            let replacement = if let Some((_, text)) = rels_text.iter().find(|(j, _)| *j == i) {
                let (filtered, n) = filter_rels(text, &source_dir(name), &doomed);
                if n > 0 {
                    removed.push(format!("{n} relationship(s) to VBA parts in {name}"));
                    Some(filtered)
                } else {
                    None
                }
            } else if name == CONTENT_TYPES {
                let text = read_text(&mut ar, i)?;
                let remaining: Vec<&String> = names.iter().filter(|n| !doomed.contains(&n.to_ascii_lowercase())).collect();
                let keep_macro_type = names.iter().any(|n| n.to_ascii_lowercase().starts_with("xl/macrosheets/"));
                if keep_macro_type {
                    kept.push("Excel 4.0 macro sheets (xl/macrosheets): kept, so the file stays macro-enabled".into());
                }
                let (new, notes) = rewrite_content_types(&text, &doomed, &remaining, keep_macro_type);
                removed.extend(notes.removed);
                kept.extend(notes.kept);
                (new != text).then_some(new)
            } else {
                None
            };
            match replacement {
                Some(text) => {
                    let src = ar.by_index_raw(i)?;
                    let mut opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
                    if let Some(t) = src.last_modified() {
                        opts = opts.last_modified_time(t);
                    }
                    out.start_file(name.as_str(), opts)?;
                    out.write_all(text.as_bytes())?;
                }
                None => out.raw_copy_file(ar.by_index_raw(i)?)?,
            }
        }
        let bytes = out.finish()?.into_inner();
        let new_extension = main_extension(&mut ZipArchive::new(Cursor::new(bytes.as_slice()))?)?;
        Ok(Cleaned { bytes, new_extension, removed, kept })
    }

    fn is_vba_name(name: &str) -> bool {
        let base = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
        base == "vbaproject.bin"
            || base == "vbadata.xml"
            || (base.starts_with("vbaprojectsignature") && base.ends_with(".bin"))
    }

    fn is_vba_rel_type(kind: &str) -> bool {
        let last = kind.rsplit('/').next().unwrap_or(kind).to_ascii_lowercase();
        last.starts_with("vbaproject") || last == "wordvbadata"
    }

    fn describe_part(name: &str) -> String {
        let base = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
        if base == "vbaproject.bin" {
            format!("VBA project {name}")
        } else if base.starts_with("vbaprojectsignature") {
            format!("VBA project signature {name}")
        } else if base == "vbadata.xml" {
            format!("VBA data {name}")
        } else {
            format!("VBA-related part {name}")
        }
    }

    fn is_rels(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower.ends_with(".rels") && (lower.starts_with("_rels/") || lower.contains("/_rels/"))
    }

    /// `xl/_rels/workbook.xml.rels` → `xl/workbook.xml` (lowercased); `_rels/.rels` → ``.
    fn source_part(rels: &str) -> String {
        let lower = rels.to_ascii_lowercase();
        let (dir, file) = match lower.rfind("_rels/") {
            Some(p) => (&lower[..p], &lower[p + 6..]),
            None => ("", lower.as_str()),
        };
        format!("{dir}{}", file.strip_suffix(".rels").unwrap_or(file))
    }

    /// Folder relative targets resolve against: `xl/_rels/workbook.xml.rels` → `xl/`.
    fn source_dir(rels: &str) -> String {
        let src = source_part(rels);
        match src.rfind('/') {
            Some(p) => src[..=p].to_string(),
            None => String::new(),
        }
    }

    /// Package path (lowercased, no leading slash) a relationship target points to.
    fn resolve(dir: &str, target: &str) -> String {
        let target = target.to_ascii_lowercase();
        let joined = match target.strip_prefix('/') {
            Some(abs) => abs.to_string(),
            None => format!("{dir}{target}"),
        };
        let mut parts: Vec<&str> = Vec::new();
        for seg in joined.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s),
            }
        }
        parts.join("/")
    }

    fn read_text(ar: &mut ZipArchive<Cursor<&[u8]>>, i: usize) -> Result<String> {
        let f = ar.by_index(i)?;
        let name = f.name().to_string();
        let mut buf = Vec::new();
        f.take(XML_CAP).read_to_end(&mut buf)?;
        String::from_utf8(buf).with_context(|| format!("{name} is not UTF-8"))
    }

    pub(super) struct Rel {
        pub kind: String,
        pub target: String,
        pub external: bool,
        /// Byte range of the whole element in the XML text.
        pub span: (usize, usize),
    }

    type Attrs<'a> = Vec<(&'a str, &'a str)>;
    type Span = (usize, usize);

    /// Elements named `tag` (not `tag` + more letters) with their attributes and byte spans.
    fn elements<'a>(xml: &'a str, tag: &str) -> Vec<(Attrs<'a>, Span)> {
        let open = format!("<{tag}");
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(p) = xml[from..].find(&open) {
            let start = from + p;
            let after = start + open.len();
            from = after;
            match xml[after..].chars().next() {
                Some(c) if c.is_whitespace() || c == '/' || c == '>' => {}
                _ => continue,
            }
            let Some(gt) = xml[after..].find('>') else { break };
            let head_end = after + gt;
            let self_closing = xml[..head_end].ends_with('/');
            let attrs_text = &xml[after..if self_closing { head_end - 1 } else { head_end }];
            let end = if self_closing {
                head_end + 1
            } else {
                let close = format!("</{tag}>");
                match xml[head_end..].find(&close) {
                    Some(c) => head_end + c + close.len(),
                    None => head_end + 1,
                }
            };
            out.push((attributes(attrs_text), (start, end)));
            from = end;
        }
        out
    }

    fn attributes(s: &str) -> Vec<(&str, &str)> {
        let mut out = Vec::new();
        let mut rest = s;
        loop {
            rest = rest.trim_start();
            let Some(eq) = rest.find('=') else { break };
            let name = rest[..eq].trim();
            rest = rest[eq + 1..].trim_start();
            let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else { break };
            let Some(close) = rest[1..].find(q) else { break };
            out.push((name, &rest[1..1 + close]));
            rest = &rest[close + 2..];
        }
        out
    }

    fn attr<'a>(attrs: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
        attrs.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }

    pub(super) fn relationships(xml: &str) -> Vec<Rel> {
        elements(xml, "Relationship")
            .into_iter()
            .map(|(a, span)| Rel {
                kind: attr(&a, "Type").unwrap_or_default().to_string(),
                target: attr(&a, "Target").unwrap_or_default().to_string(),
                external: attr(&a, "TargetMode").is_some_and(|m| m.eq_ignore_ascii_case("external")),
                span,
            })
            .collect()
    }

    fn cut(xml: &str, spans: &[(usize, usize)]) -> String {
        let mut out = String::with_capacity(xml.len());
        let mut pos = 0;
        for &(s, e) in spans {
            out.push_str(&xml[pos..s]);
            pos = e;
        }
        out.push_str(&xml[pos..]);
        out
    }

    fn filter_rels(xml: &str, dir: &str, doomed: &HashSet<String>) -> (String, usize) {
        let spans: Vec<(usize, usize)> = relationships(xml)
            .into_iter()
            .filter(|r| is_vba_rel_type(&r.kind) || (!r.external && doomed.contains(&resolve(dir, &r.target))))
            .map(|r| r.span)
            .collect();
        (cut(xml, &spans), spans.len())
    }

    #[derive(Default)]
    struct Notes {
        removed: Vec<String>,
        kept: Vec<String>,
    }

    fn rewrite_content_types(xml: &str, doomed: &HashSet<String>, remaining: &[&String], keep_macro_type: bool) -> (String, Notes) {
        let mut notes = Notes::default();
        let mut spans = Vec::new();
        let mut overridden: HashSet<String> = HashSet::new();
        for (a, span) in elements(xml, "Override") {
            let part = attr(&a, "PartName").unwrap_or_default().trim_start_matches('/').to_ascii_lowercase();
            if doomed.contains(&part) {
                spans.push(span);
            } else {
                overridden.insert(part);
            }
        }
        if !spans.is_empty() {
            notes.removed.push(format!("{} content-type override(s) for VBA parts", spans.len()));
        }
        for (a, span) in elements(xml, "Default") {
            if !attr(&a, "ContentType").unwrap_or_default().eq_ignore_ascii_case(VBA_CONTENT_TYPE) {
                continue;
            }
            let ext = format!(".{}", attr(&a, "Extension").unwrap_or_default().to_ascii_lowercase());
            let still_used = remaining
                .iter()
                .map(|n| n.to_ascii_lowercase())
                .any(|n| n.ends_with(&ext) && !overridden.contains(&n));
            if still_used {
                notes.kept.push(format!("default content type for *{ext} (another part still relies on it)"));
            } else {
                spans.push(span);
                notes.removed.push(format!("default VBA content type for *{ext}"));
            }
        }
        spans.sort_unstable();
        let mut out = cut(xml, &spans);
        if !keep_macro_type {
            for (macro_type, plain, _) in MAIN_TYPES {
                if out.contains(macro_type) {
                    out = out.replace(macro_type, plain);
                    notes.removed.push(format!("macro-enabled main content type ({macro_type} → {plain})"));
                }
            }
        }
        (out, notes)
    }

    /// Extension matching the main part's content type in the written package.
    fn main_extension(ar: &mut ZipArchive<Cursor<&[u8]>>) -> Result<Option<&'static str>> {
        let Some(i) = ar.index_for_name(CONTENT_TYPES) else { return Ok(None) };
        let xml = read_text(ar, i)?;
        for (macro_type, plain, ext) in MAIN_TYPES {
            if xml.contains(plain) {
                return Ok(Some(ext));
            }
            if xml.contains(macro_type) {
                // Only kept on purpose (Excel 4.0 macro sheets): the matching macro extension.
                return Ok(Some(match *ext {
                    "xlsx" => "xlsm",
                    "xltx" => "xltm",
                    "docx" => "docm",
                    "dotx" => "dotm",
                    "pptx" => "pptm",
                    "ppsx" => "ppsm",
                    _ => "potm",
                }));
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
                next += 1;
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

    // ---- VBA project fixtures (MS-OVBA, uncompressed chunks) ----

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
    fn write_vba<F: std::io::Read + std::io::Write + std::io::Seek>(comp: &mut cfb::CompoundFile<F>, root: &str, modules: &[(&str, &str)]) {
        let base = PathBuf::from(root);
        if root != "/" {
            comp.create_storage(&base).unwrap();
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

    const WORM: &str = "Attribute VB_Name = \"Kangatang\"\r\nSub Auto_Open()\r\nApplication.OnSheetActivate = \"x\"\r\nEnd Sub\r\n";

    fn vba_project_bin() -> Vec<u8> {
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        write_vba(&mut comp, "/", &[("Kangatang", WORM)]);
        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

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
    fn xls_encrypted_workbook_left_unchanged() {
        let mut wb = biff(true);
        // Insert FILEPASS right after the globals BOF.
        let bof_len = 4 + 16;
        let tail = wb.split_off(bof_len);
        wb.extend(rec(0x002F, &[0, 0]));
        wb.extend(tail);
        let input = ole_file(&wb);
        let out = clean(&input).unwrap();
        assert_no_vba(&out.bytes);
        assert_eq!(streams(&out.bytes)["/Workbook"], wb);
        assert!(out.kept[0].contains("encrypted"), "{:?}", out.kept);
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
}
