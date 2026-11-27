//! Genra AV core: reads a file, extracts what rules match on, and returns a verdict.
//! It never runs the file's code, never writes to it, and never sends it anywhere.

pub mod clean;
pub mod extract;
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
