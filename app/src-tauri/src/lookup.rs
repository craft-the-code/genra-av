//! Online lookup by hash prefix (ADR 0004, step 5): to check a file that nothing on the machine
//! flagged, Genra sends only the first 5 hex characters of its SHA-256 (20 bits, shared by about
//! one file in a million) and gets back every known-bad hash with that prefix; the comparison is
//! made here. The file and its full hash never leave the machine.
//!
//! **Off in this build** ([`AVAILABLE`]): the privacy policy still says Genra sends nothing by
//! itself. ADR 0004 ships the lookup together with the policy change, so `AVAILABLE` flips to true
//! in the same release as the new policy text (docs/legal/online-lookup.md). Until then no request
//! is made, whatever the setting says.

use genra_av_core::rules::Severity;
use genra_av_core::{Finding, Report};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Whether this build may ask the server at all. See the module comment before changing it.
pub const AVAILABLE: bool = false;

const URL: &str = "https://genra-api.craftthecode.dev/v1/lookup/";
pub const PREFIX_LEN: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(4);
/// An answer is kept this long (the server's lists change a few times a day).
const KEEP: Duration = Duration::from_secs(3600);
/// A prefix's answer is never this long: anything bigger is not a real answer.
const MAX_HASHES: usize = 5000;

pub const RULE: &str = "hash.online";

/// The prefix sent for a file: the first 5 hex characters of its SHA-256, lower case.
pub fn prefix(sha256: &str) -> Option<String> {
    let p = sha256.get(..PREFIX_LEN)?.to_ascii_lowercase();
    (sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit())).then_some(p)
}

/// Whether the server's answer for `sha256`'s prefix lists it. Entries with another prefix are
/// ignored (a confused or hostile answer cannot flag files outside the bucket asked about).
pub fn listed(sha256: &str, answer: &[String]) -> bool {
    let Some(p) = prefix(sha256) else { return false };
    answer.iter().any(|h| h.len() == 64 && h.to_ascii_lowercase().starts_with(&p) && h.eq_ignore_ascii_case(sha256))
}

/// The finding a match adds: "Đáng ngờ", never moved on its own (public feed data, untrusted).
pub fn finding() -> Finding {
    Finding {
        rule: RULE.into(),
        family: "hash".into(),
        severity: Severity::Suspicious,
        message_vi: "Tệp này có trong danh sách mã độc trực tuyến của Genra (danh sách công khai, chưa được xác nhận)".into(),
        message_en: Some("This file is on Genra's online list of known malware (public lists, not confirmed)".into()),
        auto_quarantine: false,
    }
}

/// Whether a report is worth a lookup: nothing on the machine flagged it already.
pub fn wants(report: &Report) -> bool {
    report.verdict.is_none_or(|v| v < Severity::Suspicious) && !report.allowed && report.findings.iter().all(|f| f.rule != RULE)
}

/// Adds the finding (and raises the verdict to suspicious) when the answer lists the file.
pub fn apply(report: &mut Report, answer: &[String]) {
    if listed(&report.sha256, answer) {
        report.findings.push(finding());
        if report.verdict.is_none_or(|v| v < Severity::Suspicious) {
            report.verdict = Some(Severity::Suspicious);
        }
    }
}

/// Answers by prefix, kept for [`KEEP`].
#[derive(Default)]
pub struct Cache {
    answers: Mutex<HashMap<String, (Instant, Vec<String>)>>,
}

impl Cache {
    /// Asks the server about `report`'s prefix (or uses a kept answer) and applies it. Any failure
    /// (offline, slow, odd answer) leaves the report as it was: the lookup only ever adds.
    pub fn check(&self, report: &mut Report) {
        if !AVAILABLE || !wants(report) {
            return;
        }
        let Some(p) = prefix(&report.sha256) else { return };
        let kept = self.answers.lock().ok().and_then(|m| m.get(&p).filter(|(at, _)| at.elapsed() < KEEP).map(|(_, a)| a.clone()));
        let answer = match kept {
            Some(a) => a,
            None => {
                let Some(a) = fetch(&p) else { return };
                if let Ok(mut m) = self.answers.lock() {
                    m.retain(|_, (at, _)| at.elapsed() < KEEP);
                    m.insert(p, (Instant::now(), a.clone()));
                }
                a
            }
        };
        apply(report, &answer);
    }
}

#[derive(serde::Deserialize)]
struct Answer {
    prefix: String,
    hashes: Vec<String>,
}

/// One GET, blocking (called from scan threads). No install id, no cookies: only the prefix.
fn fetch(prefix: &str) -> Option<Vec<String>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(concat!("genra-av-app/", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()?;
    // Debug builds only: `GENRA_AV_LOOKUP_URL` points at a local backend (`wrangler dev`).
    #[cfg(debug_assertions)]
    let base = std::env::var("GENRA_AV_LOOKUP_URL").unwrap_or_else(|_| URL.into());
    #[cfg(not(debug_assertions))]
    let base = URL;
    let res = client.get(format!("{base}{prefix}")).send().ok()?;
    if !res.status().is_success() {
        return None;
    }
    let a: Answer = res.json().ok()?;
    (a.prefix == prefix && a.hashes.len() <= MAX_HASHES).then_some(a.hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "abcde0123456789abcdef0123456789abcdef0123456789abcdef0123456789a";

    #[test]
    fn prefix_is_five_lower_hex() {
        assert_eq!(prefix(&SHA.to_uppercase()).as_deref(), Some("abcde"));
        assert_eq!(prefix("abc"), None);
        assert_eq!(prefix(&"z".repeat(64)), None);
    }

    #[test]
    fn only_an_exact_hash_in_the_same_bucket_matches() {
        assert!(listed(SHA, &[SHA.to_uppercase()]));
        assert!(!listed(SHA, &[format!("abcdf{}", &SHA[5..])]), "another bucket is ignored");
        assert!(!listed(SHA, &[format!("{}b", &SHA[..63])]));
        assert!(!listed(SHA, &[]));
    }

    #[test]
    fn a_match_makes_a_clean_file_suspicious_never_malware() {
        let mut r = genra_av_core::scan_named("a.exe", b"MZ not really", None, None);
        r.sha256 = SHA.into();
        assert!(wants(&r));
        apply(&mut r, &[SHA.into()]);
        assert_eq!(r.verdict, Some(Severity::Suspicious));
        assert!(r.findings.iter().any(|f| f.rule == RULE && !f.auto_quarantine));
        assert!(!wants(&r), "asked once");
        assert!(crate::quick::hash_only(&r), "shown as Đáng ngờ, quarantine only");
    }

    #[test]
    fn off_in_this_build() {
        let c = Cache::default();
        let mut r = genra_av_core::scan_named("a.exe", b"MZ", None, None);
        if !AVAILABLE {
            c.check(&mut r);
            assert!(r.findings.iter().all(|f| f.rule != RULE), "no request, no finding");
        }
    }

    /// Against a local backend: `wrangler dev --local --port 8799` with a known_bad row for
    /// `abcde…a`, then `GENRA_AV_LOOKUP_URL=http://localhost:8799/v1/lookup/ cargo test -p
    /// genra-av-app live_local -- --ignored`.
    #[test]
    #[ignore]
    fn live_local() {
        let answer = fetch("abcde").expect("answer");
        let sha = format!("abcde{}", "a".repeat(59));
        assert!(listed(&sha, &answer));
    }
}
