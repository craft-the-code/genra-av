//! Open Packaging Conventions (ISO/IEC 29500-2) parts the macro checks depend on:
//! `[Content_Types].xml` and `*.rels`. Parsed with a namespace-aware XML reader (quick-xml), so
//! character references, entities, namespace prefixes and attribute normalisation are handled the
//! way an XML parser in Office handles them, not by matching substrings. Rewrites re-serialise the
//! event stream; nothing is cut by byte offsets.
//!
//! Every function is linear in the input: quick-xml streams, attribute duplicate checks are done
//! only for the handful of attributes read here, nesting depth and namespace bindings are capped.

use anyhow::{bail, ensure, Context, Result};
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use quick_xml::writer::Writer;
use quick_xml::XmlVersion;
use std::collections::{HashMap, HashSet};

pub const NS_RELS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
pub const NS_CT: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
pub const NS_OFFICE_RELS: &[&str] = &[
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "http://purl.oclc.org/ooxml/officeDocument/relationships",
];
pub const NS_WORD: &[&str] = &[
    "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "http://purl.oclc.org/ooxml/wordprocessingml/main",
];
pub const NS_SHEET: &[&str] = &[
    "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "http://purl.oclc.org/ooxml/spreadsheetml/main",
];

/// Office part XML is shallow (rels and content types are depth 2); anything this deep is hostile.
const MAX_DEPTH: usize = 256;
/// Namespace bindings in scope at once; also bounds quick-xml's prefix lookup cost.
const MAX_NS_BINDINGS: usize = 512;
const BOM: &str = "\u{feff}";

/// The part's text, without a UTF-8 byte order mark. UTF-16 parts (allowed by OPC, never written
/// by Office for these parts) and invalid UTF-8 are refused rather than guessed at.
pub fn text(bytes: &[u8]) -> Result<&str> {
    ensure!(!bytes.starts_with(&[0xFF, 0xFE]) && !bytes.starts_with(&[0xFE, 0xFF]), "UTF-16 XML is not supported");
    let s = std::str::from_utf8(bytes).context("XML part is not UTF-8")?;
    Ok(s.strip_prefix(BOM).unwrap_or(s))
}

/// Package part name as compared here: no leading `/`, percent-decoded, lowercased (OPC part
/// names are case-insensitive). Applied to zip member names and to every name read from XML.
pub fn part_name(raw: &str) -> String {
    let raw = raw.split('#').next().unwrap_or(raw);
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'\\' { b'/' } else { bytes[i] });
        i += 1;
    }
    let s = String::from_utf8_lossy(&out);
    s.trim_start_matches('/').to_lowercase()
}

/// `xl/_rels/workbook.xml.rels` → `Some("xl/workbook.xml")`; `_rels/.rels` → `Some("")` (the
/// package itself). `None` if the name is not a relationships part.
pub fn rels_source(part: &str) -> Option<String> {
    let file = part.strip_suffix(".rels")?;
    let (dir, file) = match file.rfind("_rels/") {
        Some(0) => ("", &file[6..]),
        Some(p) if file.as_bytes()[p - 1] == b'/' => (&file[..p], &file[p + 6..]),
        _ => return None,
    };
    if file.contains('/') {
        return None;
    }
    Some(format!("{dir}{file}"))
}

/// Part a relationship target points to, from the relationships part's source part.
pub fn resolve(source: &str, target: &str) -> String {
    let target = part_name_keep_slash(target);
    let joined = match target.strip_prefix('/') {
        Some(abs) => abs.to_string(),
        None => {
            let dir = source.rfind('/').map_or("", |p| &source[..=p]);
            format!("{dir}{target}")
        }
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

fn part_name_keep_slash(raw: &str) -> String {
    let abs = raw.trim_start().starts_with('/') || raw.trim_start().starts_with('\\');
    let n = part_name(raw.trim());
    if abs {
        format!("/{n}")
    } else {
        n
    }
}

/// One attribute this module reads: namespace (None = unprefixed), local name, value after
/// entity decoding and XML attribute-value normalisation.
struct Wanted<'w> {
    ns: Option<&'w [&'w str]>,
    local: &'w str,
}

/// What to do with a matched element.
pub enum Action {
    Keep,
    /// Drop the element and everything inside it.
    Drop,
    /// Write it with these attribute values replaced (unprefixed attribute local name → value).
    Set(Vec<(&'static str, String)>),
}

/// Values of the wanted attributes of one element, by index in the wanted list.
pub struct Found(Vec<Option<String>>);
impl Found {
    pub fn get(&self, i: usize) -> Option<&str> {
        self.0.get(i).and_then(|v| v.as_deref())
    }
}

/// Walks `xml`; for each element whose local name is one of `elems` and whose namespace is one of
/// `ns` (or no namespace), calls `decide` with its index in `elems` and the wanted attributes.
/// With `rewrite`, returns the re-serialised document if any element was dropped or changed.
fn walk(
    xml: &str,
    ns: &[&str],
    elems: &[&str],
    wanted: &[Wanted],
    rewrite: bool,
    mut decide: impl FnMut(usize, &Found) -> Result<Action>,
) -> Result<Option<String>> {
    let mut reader = NsReader::from_str(xml);
    reader.config_mut().check_end_names = true;
    reader.config_mut().expand_empty_elements = false;
    reader.resolver_mut().set_max_namespace_bindings(MAX_NS_BINDINGS);
    let mut out = rewrite.then(|| Writer::new(Vec::with_capacity(xml.len())));
    let mut depth = 0usize;
    // Depth at which a dropped element started; everything until its End is skipped.
    let mut skipping: Option<usize> = None;
    let mut changed = false;
    loop {
        let (res, ev) = reader.read_resolved_event().map_err(|e| anyhow::anyhow!("XML: {e}"))?;
        let ns_ok = match &res {
            ResolveResult::Unbound => true,
            ResolveResult::Bound(n) => ns.contains(&n.as_ref()),
            ResolveResult::Unknown(p) => bail!("XML: undeclared namespace prefix {p}"),
        };
        let matched = match &ev {
            Event::Start(e) | Event::Empty(e) if ns_ok => elems.iter().position(|n| e.local_name().as_ref() == *n),
            _ => None,
        };
        drop(res);
        match &ev {
            Event::DocType(_) => bail!("XML: DTD declarations are not allowed in a package part"),
            Event::Decl(d) => {
                if let Some(enc) = d.encoding() {
                    let enc = enc.map_err(|e| anyhow::anyhow!("XML: {e}"))?;
                    ensure!(
                        enc.eq_ignore_ascii_case("utf-8") || enc.eq_ignore_ascii_case("utf8"),
                        "XML: encoding {enc} is not supported"
                    );
                }
            }
            Event::Eof => {
                ensure!(depth == 0, "XML: {depth} element(s) never closed");
                break;
            }
            _ => {}
        }
        let is_start = matches!(ev, Event::Start(_));
        let is_end = matches!(ev, Event::End(_));
        if is_start {
            depth += 1;
            ensure!(depth <= MAX_DEPTH, "XML: nested deeper than {MAX_DEPTH}");
        }
        if let Some(d) = skipping {
            if is_end {
                depth -= 1;
                if depth + 1 == d {
                    skipping = None;
                }
            }
            continue;
        }
        let mut action = Action::Keep;
        if let (Some(k), Event::Start(e) | Event::Empty(e)) = (matched, &ev) {
            let found = attributes(&reader, e, wanted)?;
            action = decide(k, &found)?;
        }
        if is_end {
            depth -= 1;
        }
        let Some(w) = out.as_mut() else { continue };
        match action {
            Action::Keep => w.write_event(ev).context("XML write")?,
            Action::Drop => {
                changed = true;
                if is_start {
                    skipping = Some(depth);
                }
            }
            Action::Set(values) => {
                changed = true;
                let (Event::Start(e) | Event::Empty(e)) = &ev else { bail!("XML: only elements can be changed") };
                let mut n = BytesStart::new(e.name().as_ref().to_string());
                for a in e.attributes().with_checks(false) {
                    let a = a.map_err(|e| anyhow::anyhow!("XML: {e}"))?;
                    match values.iter().find(|(k, _)| a.key.as_ref() == *k) {
                        Some((k, v)) => n.push_attribute((*k, v.as_str())),
                        None => n.push_attribute(a),
                    }
                }
                w.write_event(if is_start { Event::Start(n) } else { Event::Empty(n) }).context("XML write")?;
            }
        }
    }
    if !changed {
        return Ok(None);
    }
    let bytes = out.map(Writer::into_inner).unwrap_or_default();
    Ok(Some(String::from_utf8(bytes).context("XML write produced invalid UTF-8")?))
}

fn attributes(reader: &NsReader<&[u8]>, e: &BytesStart, wanted: &[Wanted]) -> Result<Found> {
    let mut found: Vec<Option<String>> = vec![None; wanted.len()];
    for a in e.attributes().with_checks(false) {
        let a: Attribute = a.map_err(|e| anyhow::anyhow!("XML: {e}"))?;
        if a.key.as_namespace_binding().is_some() {
            continue;
        }
        let local = a.key.local_name();
        let Some(i) = wanted.iter().position(|w| w.local == local.as_ref() && attr_ns_ok(reader, &a, w)) else { continue };
        ensure!(found[i].is_none(), "XML: duplicate attribute {}", wanted[i].local);
        let v = a.normalized_value(XmlVersion::Implicit1_0).map_err(|e| anyhow::anyhow!("XML: {e}"))?;
        found[i] = Some(v.into_owned());
    }
    Ok(Found(found))
}

fn attr_ns_ok(reader: &NsReader<&[u8]>, a: &Attribute, w: &Wanted) -> bool {
    let (res, _) = reader.resolver().resolve_attribute(a.key);
    match (w.ns, res) {
        (None, ResolveResult::Unbound) => true,
        (Some(list), ResolveResult::Bound(n)) => list.contains(&n.as_ref()),
        _ => false,
    }
}

// ---- relationships ----

#[derive(Debug, Clone)]
pub struct Rel {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub external: bool,
}

impl Rel {
    /// Last segment of the relationship type, lowercased (`.../relationships/vbaProject` →
    /// `vbaproject`). Transitional and Strict URIs share it.
    pub fn kind_name(&self) -> String {
        let k = self.kind.trim();
        k.rsplit('/').next().unwrap_or(k).to_ascii_lowercase()
    }
}

const REL_ATTRS: &[Wanted] = &[
    Wanted { ns: None, local: "Id" },
    Wanted { ns: None, local: "Type" },
    Wanted { ns: None, local: "Target" },
    Wanted { ns: None, local: "TargetMode" },
];

fn rel_of(f: &Found) -> Rel {
    Rel {
        id: f.get(0).unwrap_or_default().to_string(),
        kind: f.get(1).unwrap_or_default().to_string(),
        target: f.get(2).unwrap_or_default().to_string(),
        external: f.get(3).is_some_and(|m| m.trim().eq_ignore_ascii_case("external")),
    }
}

/// Calls `f` for every relationship. Nothing is collected, so memory stays flat however many
/// relationships the part holds.
pub fn relationships(xml: &str, mut f: impl FnMut(&Rel)) -> Result<()> {
    walk(xml, &[NS_RELS], &["Relationship"], REL_ATTRS, false, |_, found| {
        f(&rel_of(found));
        Ok(Action::Keep)
    })?;
    Ok(())
}

/// Re-serialises `xml` without the relationships `drop` selects. `None` if none was dropped.
pub fn filter_relationships(xml: &str, mut drop: impl FnMut(&Rel) -> bool) -> Result<Option<(String, Vec<Rel>)>> {
    let mut dropped = Vec::new();
    let out = walk(xml, &[NS_RELS], &["Relationship"], REL_ATTRS, true, |_, found| {
        let rel = rel_of(found);
        Ok(if drop(&rel) {
            dropped.push(rel);
            Action::Drop
        } else {
            Action::Keep
        })
    })?;
    Ok(out.map(|s| (s, dropped)))
}

// ---- content types ----

#[derive(Debug, Default)]
pub struct ContentTypes {
    /// Extension (lowercase, no dot) → content type (lowercase).
    pub defaults: HashMap<String, String>,
    /// Part name ([`part_name`]) → content type (lowercase). Only parts present in the package.
    pub overrides: HashMap<String, String>,
}

/// Attributes of Default (Extension) and Override (PartName) entries.
const CT_ATTRS: &[Wanted] = &[
    Wanted { ns: None, local: "Extension" },
    Wanted { ns: None, local: "PartName" },
    Wanted { ns: None, local: "ContentType" },
];
const CT_ELEMS: &[&str] = &["Default", "Override"];

/// One content-type entry: a Default (by extension, lowercase, no dot) or an Override (by
/// [`part_name`]), with its content type lowercased.
pub enum CtEntry<'a> {
    Default { ext: &'a str, typ: &'a str },
    Override { part: &'a str, typ: &'a str },
}

fn ct_entry<T>(k: usize, f: &Found, then: impl FnOnce(CtEntry) -> T) -> T {
    let typ = f.get(2).unwrap_or_default().trim().to_ascii_lowercase();
    if k == 0 {
        let ext = f.get(0).unwrap_or_default().trim().trim_start_matches('.').to_lowercase();
        then(CtEntry::Default { ext: &ext, typ: &typ })
    } else {
        let part = part_name(f.get(1).unwrap_or_default().trim());
        then(CtEntry::Override { part: &part, typ: &typ })
    }
}

impl ContentTypes {
    /// `present` limits overrides kept to parts that exist, so a huge list of fake overrides
    /// cannot grow memory. Two entries for the same extension or part are an error: which one
    /// Office honours is not something to guess.
    pub fn parse(xml: &str, present: &HashSet<String>) -> Result<Self> {
        let mut ct = ContentTypes::default();
        walk(xml, &[NS_CT], CT_ELEMS, CT_ATTRS, false, |k, f| {
            ct_entry(k, f, |e| match e {
                CtEntry::Default { ext, typ } => {
                    ensure!(ct.defaults.insert(ext.to_string(), typ.to_string()).is_none(), "[Content_Types].xml has two Default entries for .{ext}");
                    Ok(())
                }
                CtEntry::Override { part, typ } => {
                    if present.contains(part) {
                        ensure!(ct.overrides.insert(part.to_string(), typ.to_string()).is_none(), "[Content_Types].xml has two Override entries for /{part}");
                    }
                    Ok(())
                }
            })?;
            Ok(Action::Keep)
        })?;
        Ok(ct)
    }

    pub fn type_of(&self, part: &str) -> Option<&str> {
        if let Some(t) = self.overrides.get(part) {
            return Some(t);
        }
        let base = part.rsplit('/').next().unwrap_or(part);
        let ext = base.rsplit_once('.').map(|(_, e)| e)?;
        self.defaults.get(ext).map(String::as_str)
    }
}

/// What to do with a content-type entry.
pub enum CtAction {
    Keep,
    Drop,
    SetType(String),
}

/// Re-serialises `[Content_Types].xml` applying `decide` to each Default and Override entry.
/// `None` if nothing changed.
pub fn rewrite_content_types(xml: &str, mut decide: impl FnMut(CtEntry) -> CtAction) -> Result<Option<String>> {
    walk(xml, &[NS_CT], CT_ELEMS, CT_ATTRS, true, |k, f| {
        Ok(match ct_entry(k, f, &mut decide) {
            CtAction::Keep => Action::Keep,
            CtAction::Drop => Action::Drop,
            CtAction::SetType(t) => Action::Set(vec![("ContentType", t)]),
        })
    })
}

// ---- other parts ----

/// Re-serialises a WordprocessingML settings part without `<w:attachedTemplate r:id="...">`
/// elements whose relationship id is in `ids`.
pub fn drop_attached_template(xml: &str, ids: &HashSet<String>) -> Result<Option<String>> {
    let wanted = [Wanted { ns: Some(NS_OFFICE_RELS), local: "id" }];
    walk(xml, NS_WORD, &["attachedTemplate"], &wanted, true, |_, f| {
        Ok(match f.get(0) {
            Some(id) if ids.contains(id) => Action::Drop,
            _ => Action::Keep,
        })
    })
}

/// Names of SpreadsheetML defined names (`<definedName name="...">`) that Excel runs on open or
/// close (Auto_Open, Auto_Close and their numbered variants, also as `_xlnm.` built-ins).
pub fn auto_run_names(xml: &str) -> Result<Vec<String>> {
    let wanted = [Wanted { ns: None, local: "name" }];
    let mut out = Vec::new();
    walk(xml, NS_SHEET, &["definedName"], &wanted, false, |_, f| {
        if let Some(n) = f.get(0) {
            if is_auto_run_name(n) {
                out.push(n.to_string());
            }
        }
        Ok(Action::Keep)
    })?;
    Ok(out)
}

/// `Auto_Open`, `auto_close2`, `_xlnm.Auto_Open`, ...: Excel runs the macro such a name points to.
pub fn is_auto_run_name(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    let n = n.strip_prefix("_xlnm.").unwrap_or(&n);
    n.starts_with("auto_open") || n.starts_with("auto_close") || n.starts_with("auto_activate") || n.starts_with("auto_deactivate")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_names_normalise() {
        assert_eq!(part_name("/XL/vbaProject%2Ebin"), "xl/vbaproject.bin");
        assert_eq!(part_name("xl\\a.bin"), "xl/a.bin");
        assert_eq!(part_name("%"), "%");
        assert_eq!(part_name("a%4"), "a%4");
        assert_eq!(rels_source("xl/_rels/workbook.xml.rels").as_deref(), Some("xl/workbook.xml"));
        assert_eq!(rels_source("_rels/.rels").as_deref(), Some(""));
        assert_eq!(rels_source("xl/my_rels/a.rels"), None);
        assert_eq!(resolve("xl/workbook.xml", "../customXml/item1.xml"), "customxml/item1.xml");
        assert_eq!(resolve("xl/workbook.xml", "/xl/vbaProject.bin"), "xl/vbaproject.bin");
        assert_eq!(resolve("xl/workbook.xml", "data.bin"), "xl/data.bin");
    }

    #[test]
    fn relationships_decode_references_and_prefixes() {
        let xml = r#"<r:Relationships xmlns:r="http://schemas.openxmlformats.org/package/2006/relationships"><r:Relationship Id="a" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProjec&#116;" Target="data.bin"/></r:Relationships>"#;
        let mut got = Vec::new();
        relationships(xml, |r| got.push(r.clone())).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind_name(), "vbaproject");
        assert_eq!(got[0].target, "data.bin");
    }

    #[test]
    fn foreign_namespace_element_is_not_a_relationship() {
        let xml = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships" xmlns:x="urn:x"><x:Relationship Id="a" Type="t" Target="b"/></Relationships>"#;
        let mut n = 0;
        relationships(xml, |_| n += 1).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn hostile_xml_is_an_error() {
        assert!(relationships("<!DOCTYPE x [<!ENTITY e \"vbaProject\">]><Relationships/>", |_| {}).is_err());
        assert!(relationships(r#"<Relationships><Relationship Type="&e;"/></Relationships>"#, |_| {}).is_err());
        assert!(relationships(r#"<Relationships><Relationship Type="a" Type="b"/></Relationships>"#, |_| {}).is_err());
        assert!(relationships(r#"<Relationships><Relationship>"#, |_| {}).is_err());
        assert!(relationships(r#"<?xml version="1.0" encoding="UTF-7"?><Relationships/>"#, |_| {}).is_err());
        assert!(relationships(r#"<p:Relationships/>"#, |_| {}).is_err());
        assert!(text(&[0xFF, 0xFE, b'<', 0]).is_err());
    }

    #[test]
    fn filter_reserialises() {
        let xml = r#"<?xml version="1.0"?><Relationships><Relationship Id="1" Type="x/worksheet" Target="a"/><Relationship Id="2" Type="x/vbaProject" Target="b"></Relationship><!-- c --></Relationships>"#;
        let (out, dropped) = filter_relationships(xml, |r| r.kind_name() == "vbaproject").unwrap().unwrap();
        assert_eq!(out, r#"<?xml version="1.0"?><Relationships><Relationship Id="1" Type="x/worksheet" Target="a"/><!-- c --></Relationships>"#);
        assert_eq!(dropped.len(), 1);
        assert!(filter_relationships(xml, |_| false).unwrap().is_none());
    }
}
