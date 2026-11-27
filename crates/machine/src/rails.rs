//! Safety rails applied after a scan and before anything is moved (ADR 0004).
//!
//! A trusted hash list can quarantine without asking. If that list were ever wrong about a file
//! (a mislabelled entry, a poisoned feed), the damage is largest for files every PC has: signed
//! system and vendor programs. So a file that carries a valid Authenticode signature is never
//! quarantined on hash evidence alone; its hash hits are lowered to "suspicious" and the user is
//! asked, as for any other suspicious file. The same holds for YARA rules (a rule set written by
//! others, rated malware in the pack): signature evidence alone never moves a signed program.
//! Genra's own pack rules and the built-in checks are not affected.

use genra_av_core::rules::Severity;
use genra_av_core::{Finding, Report};
use std::path::Path;

/// Lowers trusted hash hits on a validly signed file. Returns true when it changed the report.
/// Asks Windows about the signature only when a trusted hash hit is the sole reason to quarantine,
/// which is rare, so scans stay fast. Elsewhere it does nothing (the trusted lists target Windows
/// programs; macOS and Linux files are not quarantined on hash evidence by the app).
pub fn signed_file_rail(report: &mut Report, path: &Path) -> bool {
    let serious: Vec<&Finding> = report.findings.iter().filter(|f| f.severity >= Severity::Suspicious).collect();
    let listed = |f: &Finding| f.rule.starts_with("hash.") || f.rule.starts_with("yara.");
    let hash_alone = !serious.is_empty() && serious.iter().all(|f| listed(f));
    let would_quarantine = serious.iter().any(|f| f.auto_quarantine && f.severity == Severity::Malware);
    if !(hash_alone && would_quarantine) || !validly_signed(path) {
        return false;
    }
    for f in report.findings.iter_mut().filter(|f| listed(f)) {
        f.severity = Severity::Suspicious;
        f.auto_quarantine = false;
    }
    report.findings.push(Finding {
        rule: "rail.signed_file".into(),
        family: "signed".into(),
        severity: Severity::Info,
        message_vi: "Tệp có chữ ký số hợp lệ nên Genra không tự cách ly chỉ vì trùng danh sách; bạn quyết định.".into(),
        message_en: Some("The file has a valid digital signature, so Genra does not quarantine it on a list match alone; you decide.".into()),
        auto_quarantine: false,
    });
    report.verdict = report.findings.iter().map(|f| f.severity).max();
    true
}

#[cfg(windows)]
fn validly_signed(path: &Path) -> bool {
    use std::time::Duration;
    let p = path.display().to_string();
    let Ok(o) = crate::proc::powershell(&crate::startup::signature_script(&[], std::slice::from_ref(&p)), Duration::from_secs(30)) else {
        return false;
    };
    let (_, sig) = crate::startup::parse_signature_json(&o.stdout);
    sig.get(&p.to_lowercase()).is_some_and(|(signed, _)| *signed == Some(true))
}

#[cfg(not(windows))]
fn validly_signed(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(findings: Vec<Finding>) -> Report {
        let verdict = findings.iter().map(|f| f.severity).max();
        Report { sha256: "0".repeat(64), kind: genra_av_core::extract::Kind::Other, vba_modules: vec![], findings, verdict, allowed: false }
    }

    fn hash_hit(trusted: bool) -> Finding {
        Finding {
            rule: "hash.trusted-1".into(),
            family: "x".into(),
            severity: if trusted { Severity::Malware } else { Severity::Suspicious },
            message_vi: String::new(),
            message_en: None,
            auto_quarantine: trusted,
        }
    }

    #[test]
    fn leaves_reports_alone_unless_a_trusted_hash_is_the_only_reason() {
        let mut r = report(vec![hash_hit(false)]);
        assert!(!signed_file_rail(&mut r, Path::new("/nonexistent")), "untrusted feed: nothing to lower");
        let mut r = report(vec![hash_hit(true)]);
        // Not signed (or not Windows): the trusted hit stands.
        assert!(!signed_file_rail(&mut r, Path::new("/nonexistent")));
        assert_eq!(r.verdict, Some(Severity::Malware));
    }
}
