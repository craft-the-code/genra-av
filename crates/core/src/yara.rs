//! YARA rules for malware families (ADR 0004, layer 2): the shared rule language, run by
//! [boreal](https://github.com/vthib/boreal) (pure Rust, MIT/Apache-2.0).
//!
//! Why boreal and not YARA-X (measured 27/11 on the same 2 865 licensed rules): YARA-X adds about
//! 17 MB to the program (it compiles rules to WebAssembly and carries wasmtime), boreal about
//! 2.6 MB; boreal also compiled the set ten times faster and scanned about twice as fast. The
//! engine sits behind this module only, so swapping it is one file.
//!
//! Rules travel as source in the signed pack (beside the JSON, named by its digest like the hash
//! lists) and compile once when the pack loads. Every finding is `suspicious` unless the rule's
//! `genra_severity` meta says `malware`, which the pack pipeline only writes for rules with no
//! match on the clean corpus. A scan of one file stops after [`TIMEOUT`].

use crate::rules::Severity;
use crate::Finding;
use anyhow::{bail, Result};
use std::time::Duration;

/// Most time one file may take (a slow rule on a crafted file cannot hang a scan).
pub const TIMEOUT: Duration = Duration::from_millis(1500);
/// Files larger than this are not given to the rules (the scanner reads at most 100 MB anyway).
pub const MAX_BYTES: usize = 32 * 1024 * 1024;
/// The engine and its version, part of the scan cache fingerprint.
pub const ENGINE: &str = "boreal-1.4";

pub struct YaraRules {
    scanner: boreal::Scanner,
    count: usize,
}

impl std::fmt::Debug for YaraRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "YaraRules({} rules)", self.count)
    }
}

/// Number of `rule` declarations in a source (for the pack's count check).
pub fn count_rules(source: &str) -> usize {
    source.lines().filter(|l| rule_name(l).is_some()).count()
}

/// The name declared on a line `[private|global] rule NAME [: tags] [{]`, if it is one.
fn rule_name(line: &str) -> Option<&str> {
    // At the start of the line only, as scripts/yara_select.py counts them.
    if line.starts_with(char::is_whitespace) {
        return None;
    }
    let mut w = line.split_whitespace();
    let mut t = w.next()?;
    while t == "private" || t == "global" {
        t = w.next()?;
    }
    if t != "rule" {
        return None;
    }
    let t = w.next()?;
    let end = t.bytes().position(|b| !(b.is_ascii_alphanumeric() || b == b'_')).unwrap_or(t.len());
    (end > 0).then(|| &t[..end])
}

impl YaraRules {
    /// Compiles a whole rule file. The pack pipeline has already compiled every rule on its own
    /// with this engine, so any error here means a damaged or mismatched file: it is refused.
    pub fn compile(source: &str) -> Result<YaraRules> {
        let mut c = boreal::Compiler::new();
        if let Err(e) = c.add_rules_str(source) {
            bail!("YARA rules do not compile: {e:?}");
        }
        let mut scanner = c.finalize();
        scanner.set_scan_params(boreal::scanner::ScanParams::default().timeout_duration(Some(TIMEOUT)).string_max_nb_matches(100));
        Ok(YaraRules { scanner, count: count_rules(source) })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The rules that match `bytes`, as findings. A scan that runs out of time reports what it
    /// matched so far.
    pub fn findings(&self, bytes: &[u8]) -> Vec<Finding> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Vec::new();
        }
        let result = match self.scanner.scan_mem(bytes) {
            Ok(r) => r,
            Err((_, partial)) => partial,
        };
        let mut out = Vec::new();
        for r in result.rules.iter().filter(|r| r.matched) {
            let meta = |key: &str| {
                r.metadatas.iter().find(|m| self.scanner.get_string_symbol(m.name) == key).and_then(|m| match m.value {
                    boreal::MetadataValue::Bytes(b) => Some(String::from_utf8_lossy(self.scanner.get_bytes_symbol(b)).into_owned()),
                    _ => None,
                })
            };
            let severity = if meta("genra_severity").as_deref() == Some("malware") { Severity::Malware } else { Severity::Suspicious };
            let family = meta("malware_family").or_else(|| meta("malware")).or_else(|| meta("family")).filter(|f| !f.trim().is_empty()).unwrap_or_else(|| family_from_name(r.name));
            out.push(Finding {
                rule: format!("yara.{}", r.name),
                severity,
                message_vi: format!("Tệp khớp dấu hiệu nhận dạng của mã độc {family}."),
                message_en: Some(format!("The file matches the signature of the {family} malware.")),
                family,
                auto_quarantine: severity == Severity::Malware,
            });
        }
        out
    }
}

/// A family name read from a rule name such as `DITEKSHEN_MALWARE_Win_AgentTesla` or
/// `SIGNATURE_BASE_APT_MAL_Emotet_Loader_Jan23`: the words after the vendor and the generic
/// tags, up to the first date-like or numeric word.
pub fn family_from_name(name: &str) -> String {
    const GENERIC: &[&str] = &[
        "malware", "mal", "win", "win32", "win64", "windows", "apt", "susp", "suspicious", "crime", "crimeware", "hktl", "hacktool", "exe", "dll", "loader",
        "trojan", "ransomware", "ransom", "rat", "backdoor", "stealer", "infostealer", "dropper", "downloader", "generic", "gen", "pe", "x64", "x86", "elf", "macho",
        "file", "mem", "memory", "detection", "rule", "base", "signature", "ditekshen", "eset", "volexity", "gcti", "sekoia", "mandiant", "fireeye", "trellix", "arc",
        "withsecure", "elceef", "reversinglabs", "rl", "byte", "string", "strings",
    ];
    let words: Vec<&str> = name.split('_').filter(|w| !w.is_empty()).collect();
    let mut picked: Vec<&str> = Vec::new();
    for w in &words {
        let l = w.to_ascii_lowercase();
        if GENERIC.contains(&l.as_str()) {
            if picked.is_empty() {
                continue;
            }
            break;
        }
        if w.bytes().all(|b| b.is_ascii_digit()) || (w.len() >= 4 && w.bytes().filter(|b| b.is_ascii_digit()).count() * 2 > w.len()) {
            break;
        }
        picked.push(w);
        if picked.len() == 2 {
            break;
        }
    }
    if picked.is_empty() {
        name.to_string()
    } else {
        picked.join(" ")
    }
}

/// The line that separates rule blocks in the pack pipeline's selection file.
pub const BLOCK_MARK: &str = "// @genra-rule";

/// Compiles `header` + each block in order, keeping the blocks that compile (a block may use the
/// rules kept before it). Returns the names of the refused blocks' rules and how many rules were
/// kept; the kept set is compiled whole once more, and if that fails every rule is refused.
pub fn check_blocks(text: &str) -> (Vec<String>, usize) {
    let sep = format!("\n{BLOCK_MARK}\n");
    let mut parts = text.split(sep.as_str());
    let header = parts.next().unwrap_or("").to_string();
    let mut kept = header.clone();
    let mut refused = Vec::new();
    let mut n = 0;
    // One compiler, one block at a time (each with the imports): a refused block adds nothing,
    // and a block may use the rules accepted before it.
    let mut c = boreal::Compiler::new();
    for block in parts {
        let names: Vec<String> = block.lines().filter_map(rule_name).map(str::to_string).collect();
        if c.add_rules_str(format!("{header}\n{block}\n")).is_ok() {
            kept.push('\n');
            kept.push_str(block);
            kept.push('\n');
            n += names.len();
        } else {
            refused.extend(names);
        }
    }
    if n > 0 && YaraRules::compile(&kept).is_err() {
        refused.extend(kept.lines().filter_map(rule_name).map(str::to_string));
        n = 0;
    }
    (refused, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
import "pe"
rule DITEKSHEN_MALWARE_Win_DemoStealer : FILE {
    meta:
        description = "test"
        author = "test"
    strings:
        $a = "genra-demo-stealer-marker" ascii wide
    condition:
        $a
}
private rule helper { condition: filesize < 10 }
rule SIGNATURE_BASE_Demo_Confirmed {
    meta:
        malware_family = "DemoFamily"
        genra_severity = "malware"
    strings:
        $b = { 47 45 4E 52 41 2D 42 41 44 }
    condition:
        $b
}
"#;

    #[test]
    fn matches_become_findings() {
        let y = YaraRules::compile(RULES).unwrap();
        assert_eq!(y.len(), 3);
        assert!(y.findings(b"nothing here").is_empty());
        let f = y.findings(b"xx genra-demo-stealer-marker yy");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "yara.DITEKSHEN_MALWARE_Win_DemoStealer");
        assert_eq!(f[0].family, "DemoStealer");
        assert_eq!(f[0].severity, Severity::Suspicious);
        assert!(!f[0].auto_quarantine, "suspicious never moves a file on its own");
        let f = y.findings(b"..GENRA-BAD..");
        assert_eq!((f[0].family.as_str(), f[0].severity, f[0].auto_quarantine), ("DemoFamily", Severity::Malware, true));
    }

    #[test]
    fn blocks_are_checked_one_by_one() {
        let text = format!(
            "import \"pe\"\n{m}\nrule good {{ condition: pe.number_of_sections > 0 }}\n{m}\nrule bad {{ condition: no_such_thing }}\n{m}\nrule uses_good {{ condition: good }}\n{m}\nrule uses_bad {{ condition: bad }}",
            m = BLOCK_MARK
        );
        let (refused, kept) = check_blocks(&text);
        assert_eq!(refused, ["bad", "uses_bad"]);
        assert_eq!(kept, 2);
    }

    #[test]
    fn a_broken_file_is_refused() {
        assert!(YaraRules::compile("rule x { condition: nope_unknown }").is_err());
    }

    #[test]
    fn rule_names_and_families() {
        assert_eq!(count_rules("rule a {\n}\nprivate rule b : T {\n  // rule c\n"), 2);
        assert_eq!(family_from_name("DITEKSHEN_MALWARE_Win_AgentTesla"), "AgentTesla");
        assert_eq!(family_from_name("SIGNATURE_BASE_APT_MAL_Emotet_Loader_Jan23"), "Emotet");
        assert_eq!(family_from_name("ESET_Turla_Kazuar_2023"), "Turla Kazuar");
        assert_eq!(family_from_name("Win32_Ransomware_Conti"), "Conti");
        assert_eq!(family_from_name("GENERIC"), "GENERIC");
    }
}
