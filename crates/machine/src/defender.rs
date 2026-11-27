//! Microsoft Defender as a second opinion (ADR 0004, layer 4).
//!
//! When Genra's own layers call a file *suspicious*, and Defender is this computer's antivirus
//! (on, not in passive mode), Genra asks it about that one file with
//! `MpCmdRun.exe -Scan -ScanType 3 -File <path> -DisableRemediation`: Defender reports, it does
//! not act. A detection in a malware category (Trojan, Backdoor, Worm, Virus, Ransom, PWS,
//! Spyware) makes the finding *malware*, with Defender's own name for it; a detection in another
//! category (hack tools, unwanted software, remote access) is shown but changes nothing.
//!
//! Office documents are not sent to Defender: their macros have Genra's own path ("Dọn sạch
//! giúp tôi" keeps the data), and a document is what Defender's sample submission would upload
//! with the user's own data in it. Genra sends nothing itself; Defender follows its own settings.
//!
//! The pack can switch the layer off (`disabled: ["defender"]`) or one Defender name, by its rule
//! id ([`rule_id`]: `Trojan:Win32/Wacatac.B!ml` is `defender.Trojan_Win32_Wacatac.B_ml`).

use genra_av_core::rules::Severity;
use genra_av_core::{Finding, Report};
use std::path::Path;

/// The id of every finding from this layer starts with this; `pack.disabled` may hold it alone
/// to switch the layer off.
pub const RULE: &str = "defender";

/// Defender categories that mean malware. Anything else Defender names (HackTool, PUA,
/// RemoteAccess, Program, Exploit…) is reported but never raises the verdict: those are often
/// tools an office machine uses on purpose.
const MALWARE: &[&str] = &[
    "Trojan", "TrojanDownloader", "TrojanDropper", "TrojanSpy", "TrojanProxy", "TrojanClicker", "TrojanNotifier", "Backdoor", "Worm", "Virus", "Ransom", "PWS",
    "Spyware",
];

/// The finding's rule id for a Defender name: `defender.` and the name with every character
/// outside `[A-Za-z0-9._-]` as `_`, at most 80 characters (what reports and `disabled` accept).
pub fn rule_id(name: &str) -> String {
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }).collect();
    let mut id = format!("{RULE}.{safe}");
    id.truncate(80);
    id
}

/// What Defender said about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Said {
    Clean,
    /// Defender's name for the threat (`Trojan:Win32/Wacatac.B!ml`), or `None` when it reported
    /// a threat Genra could not read the name of.
    Threat(Option<String>),
}

/// True when Genra would ask Defender about this file: something on it is suspicious, nothing on
/// it already moves it, it is not an Office document, and Defender was not asked yet.
pub fn wants(report: &Report, path: &Path) -> bool {
    report.verdict == Some(Severity::Suspicious)
        && !report.allowed
        && !report.should_quarantine()
        && !crate::repair::is_office_document(path)
        && !report.findings.iter().any(|f| f.rule == RULE || f.rule.starts_with("defender."))
        && path.is_absolute()
}

/// Asks Defender when [`wants`] says so and Defender is on, and adds what it said to the report.
/// Returns true when Defender was actually run (not answered from this session's memory), so a
/// caller can bound how many files one scan sends to it.
pub fn second_opinion(report: &mut Report, path: &Path, disabled: &[String]) -> bool {
    if disabled.iter().any(|d| d == RULE) || !wants(report, path) {
        return false;
    }
    let Some((said, ran)) = ask(path, &report.sha256) else { return false };
    apply(report, &said, disabled);
    ran
}

/// Adds Defender's answer to the report and recomputes the verdict.
pub fn apply(report: &mut Report, said: &Said, disabled: &[String]) {
    let f = finding(said);
    if disabled.iter().any(|d| d == &f.rule) {
        return;
    }
    report.findings.push(f);
    report.verdict = report.findings.iter().map(|f| f.severity).max();
}

fn finding(said: &Said) -> Finding {
    match said {
        Said::Clean => Finding {
            rule: "defender.clean".into(),
            family: RULE.into(),
            severity: Severity::Info,
            message_vi: "Genra đã hỏi thêm Windows Defender: Defender không thấy mã độc trong tệp này.".into(),
            message_en: Some("Genra also asked Windows Defender: it found no malware in this file.".into()),
            auto_quarantine: false,
        },
        Said::Threat(Some(name)) if is_malware(name) => Finding {
            rule: rule_id(name),
            family: family_of(name),
            severity: Severity::Malware,
            message_vi: format!("Windows Defender cũng nhận ra tệp này là mã độc ({name})."),
            message_en: Some(format!("Windows Defender also detects this file as malware ({name}).")),
            auto_quarantine: true,
        },
        Said::Threat(name) => {
            let n = name.as_deref().unwrap_or("?");
            Finding {
                rule: rule_id(name.as_deref().unwrap_or("unknown")),
                family: name.as_deref().map(family_of).unwrap_or_else(|| RULE.into()),
                severity: Severity::Suspicious,
                message_vi: format!("Windows Defender cũng cảnh báo tệp này ({n}) nhưng không xếp là mã độc: có thể là công cụ hoặc phần mềm không mong muốn."),
                message_en: Some(format!("Windows Defender also warns about this file ({n}) but does not call it malware: it may be a tool or unwanted software.")),
                auto_quarantine: false,
            }
        }
    }
}

/// `Trojan:Win32/Wacatac.B!ml` → is `Trojan` a malware category.
pub fn is_malware(name: &str) -> bool {
    name.split_once(':').is_some_and(|(cat, _)| MALWARE.contains(&cat))
}

/// `Trojan:Win32/AgentTesla.RV!MTB` → `AgentTesla`.
pub fn family_of(name: &str) -> String {
    let after = name.split_once('/').map(|(_, f)| f).unwrap_or(name);
    let fam = after.split(['.', '!']).next().unwrap_or(after);
    if fam.is_empty() { RULE.into() } else { fam.to_string() }
}

/// A Defender threat name: `Category:Platform/Family…`, the category letters only (3 or more,
/// so `C:\…` paths are not taken for one), a platform before the slash, no spaces.
fn threat_name(token: &str) -> Option<&str> {
    let token = token.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | '(' | ')'));
    let (cat, rest) = token.split_once(':')?;
    let (platform, family) = rest.split_once('/')?;
    let ok = cat.len() >= 3
        && cat.bytes().all(|b| b.is_ascii_alphabetic())
        && !platform.is_empty()
        && platform.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !family.is_empty()
        && token.bytes().all(|b| b.is_ascii_graphic() && b != b'\\');
    ok.then_some(token)
}

/// MpCmdRun's exit code and output → what it said. 0 is clean, 2 is "threats found"; anything
/// else (Defender off, the file gone, a timeout) is no answer. The name is found by its shape,
/// not by the label before it, which Windows may translate.
pub fn parse_scan(code: Option<i32>, stdout: &str) -> Option<Said> {
    match code {
        Some(0) => Some(Said::Clean),
        Some(2) => Some(Said::Threat(stdout.split_whitespace().find_map(threat_name).map(str::to_string))),
        _ => None,
    }
}

/// The status script's JSON → MpCmdRun's folder, when Defender is this computer's antivirus.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_status(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json.trim_start_matches('\u{feff}').trim()).ok()?;
    let on = v.get("av").and_then(|x| x.as_bool()) == Some(true);
    // Passive mode: another antivirus is in charge, and the user chose it.
    let mode = v.get("mode").and_then(|x| x.as_str()).unwrap_or("");
    if !on || !(mode.is_empty() || mode.eq_ignore_ascii_case("Normal")) {
        return None;
    }
    Some(v.get("dir").and_then(|x| x.as_str()).unwrap_or("").to_string())
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    const STATUS_TTL: Duration = Duration::from_secs(600);
    const SCAN_TIMEOUT: Duration = Duration::from_secs(90);

    static STATUS: Mutex<Option<(Instant, Option<PathBuf>)>> = Mutex::new(None);
    /// sha256 → what Defender said, for this session: a file asked about during the scan is not
    /// sent again when the user opens it or presses "Dọn sạch giúp tôi".
    static SAID: Mutex<Option<HashMap<String, Said>>> = Mutex::new(None);

    const STATUS_SCRIPT: &str = "$o=@{};\
        try{$m=Get-MpComputerStatus -ErrorAction Stop;$o.av=[bool]$m.AntivirusEnabled;$o.mode=[string]$m.AMRunningMode}catch{};\
        try{$o.dir=[string](Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender' -Name InstallLocation -ErrorAction Stop).InstallLocation}catch{};\
        $o|ConvertTo-Json -Compress";

    /// MpCmdRun.exe when Defender is on; looked up once every ten minutes.
    fn mpcmdrun() -> Option<PathBuf> {
        let mut g = STATUS.lock().ok()?;
        if let Some((at, p)) = g.as_ref() {
            if at.elapsed() < STATUS_TTL {
                return p.clone();
            }
        }
        let found = crate::proc::powershell(STATUS_SCRIPT, Duration::from_secs(30)).ok().and_then(|o| parse_status(&o.stdout)).and_then(|dir| {
            // The platform folder Defender updates itself into, then the one Windows ships.
            let platform = Some(PathBuf::from(dir).join("MpCmdRun.exe")).filter(|p| p.is_absolute() && p.is_file());
            platform.or_else(|| {
                std::env::var_os("ProgramFiles").map(|pf| PathBuf::from(pf).join("Windows Defender").join("MpCmdRun.exe")).filter(|p| p.is_file())
            })
        });
        *g = Some((Instant::now(), found.clone()));
        found
    }

    pub fn ask(path: &Path, sha256: &str) -> Option<(Said, bool)> {
        if let Some(s) = SAID.lock().ok().and_then(|g| g.as_ref().and_then(|m| m.get(sha256).cloned())) {
            return Some((s, false));
        }
        let mp = mpcmdrun()?;
        let file = path.to_str()?;
        let out = crate::proc::run(mp.to_str()?, &["-Scan", "-ScanType", "3", "-File", file, "-DisableRemediation"], SCAN_TIMEOUT).ok()?;
        let said = parse_scan(out.status, &out.stdout)?;
        if let Ok(mut g) = SAID.lock() {
            g.get_or_insert_with(HashMap::new).insert(sha256.to_string(), said.clone());
        }
        Some((said, true))
    }
}

#[cfg(windows)]
use imp::ask;

#[cfg(not(windows))]
fn ask(_path: &Path, _sha256: &str) -> Option<(Said, bool)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(findings: Vec<Finding>) -> Report {
        let verdict = findings.iter().map(|f| f.severity).max();
        Report { sha256: "0".repeat(64), kind: genra_av_core::extract::Kind::Other, vba_modules: vec![], findings, verdict, allowed: false }
    }

    fn suspicious(rule: &str) -> Finding {
        Finding { rule: rule.into(), family: "script".into(), severity: Severity::Suspicious, message_vi: String::new(), message_en: None, auto_quarantine: false }
    }

    const OUT: &str = "Scan starting...\r\nScan finished.\r\nScanning C:\\Users\\An\\Downloads\\hoa-don.js found 1 threats.\r\n\r\n\
        <===========================LIST OF DETECTED THREATS==========================>\r\n\
        ----------------------------- Threat information ------------------------------\r\n\
        Threat                  : TrojanDownloader:JS/Nemucod.ABC!MTB\r\n\
        Resources               : 1 total\r\n    file                : C:\\Users\\An\\Downloads\\hoa-don.js\r\n";

    #[test]
    fn reads_the_exit_code_and_the_name_by_its_shape() {
        assert_eq!(parse_scan(Some(0), "Scan finished."), Some(Said::Clean));
        assert_eq!(parse_scan(Some(2), OUT), Some(Said::Threat(Some("TrojanDownloader:JS/Nemucod.ABC!MTB".into()))));
        // A translated label, and a drive path that looks like "x:y" are not names.
        let vi = "Mối đe dọa              : Virus:DOS/EICAR_Test_File\r\n    tệp : C:/Temp/a.com http://x/y";
        assert_eq!(parse_scan(Some(2), vi), Some(Said::Threat(Some("Virus:DOS/EICAR_Test_File".into()))));
        assert_eq!(parse_scan(Some(2), "found 1 threats. C:\\a\\b.exe"), Some(Said::Threat(None)));
        assert_eq!(parse_scan(Some(1), OUT), None, "an error is no answer");
        assert_eq!(parse_scan(None, OUT), None, "a timeout is no answer");
    }

    #[test]
    fn only_malware_categories_raise_the_verdict() {
        assert!(is_malware("Trojan:Win32/Wacatac.B!ml"));
        assert!(is_malware("Virus:DOS/EICAR_Test_File"));
        assert!(!is_malware("HackTool:Win32/Mimikatz"));
        assert!(!is_malware("RemoteAccess:Win32/AnyDesk"));
        assert!(!is_malware("PUA:Win32/Presenoker"));
        assert_eq!(family_of("Trojan:Win32/AgentTesla.RV!MTB"), "AgentTesla");
        assert_eq!(family_of("Virus:DOS/EICAR_Test_File"), "EICAR_Test_File");

        let mut r = report(vec![suspicious("builtin.script_download_run")]);
        apply(&mut r, &Said::Threat(Some("Trojan:Win32/AgentTesla.RV!MTB".into())), &[]);
        assert_eq!(r.verdict, Some(Severity::Malware));
        assert!(r.should_quarantine());
        assert!(r.findings.last().unwrap().message_vi.contains("AgentTesla.RV!MTB"));

        let mut r = report(vec![suspicious("builtin.script_download_run")]);
        apply(&mut r, &Said::Threat(Some("HackTool:Win32/Mimikatz".into())), &[]);
        assert_eq!(r.verdict, Some(Severity::Suspicious));
        assert!(!r.should_quarantine());

        let mut r = report(vec![suspicious("builtin.script_download_run")]);
        apply(&mut r, &Said::Threat(None), &[]);
        assert!(!r.should_quarantine(), "a threat without a readable name is not trusted to move a file");

        let mut r = report(vec![suspicious("builtin.script_download_run")]);
        apply(&mut r, &Said::Clean, &[]);
        assert_eq!(r.verdict, Some(Severity::Suspicious), "Defender's silence never clears Genra's own finding");
    }

    #[test]
    fn the_pack_can_switch_off_one_name_or_the_layer() {
        let name = "Trojan:Win32/Wacatac.B!ml";
        let mut r = report(vec![suspicious("x")]);
        assert_eq!(rule_id(name), "defender.Trojan_Win32_Wacatac.B_ml");
        assert!(rule_id(&"A".repeat(200)).len() == 80);
        apply(&mut r, &Said::Threat(Some(name.into())), &["defender.Trojan_Win32_Wacatac.B_ml".into()]);
        assert_eq!(r.verdict, Some(Severity::Suspicious));
        let mut r = report(vec![suspicious("x")]);
        assert!(!second_opinion(&mut r, Path::new("C:\\a.js"), &["defender".into()]));
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn asks_only_about_suspicious_files_that_are_not_office_documents() {
        let abs = if cfg!(windows) { "C:\\Users\\An\\a.js" } else { "/home/an/a.js" };
        assert!(wants(&report(vec![suspicious("x")]), Path::new(abs)));
        assert!(!wants(&report(vec![suspicious("x")]), Path::new("a.js")), "relative path");
        let doc = if cfg!(windows) { "C:\\Users\\An\\a.xlsm" } else { "/home/an/a.xlsm" };
        assert!(!wants(&report(vec![suspicious("x")]), Path::new(doc)));
        let mut malware = suspicious("pack.rule");
        malware.severity = Severity::Malware;
        malware.auto_quarantine = true;
        assert!(!wants(&report(vec![malware]), Path::new(abs)), "already moved by Genra's own evidence");
        assert!(!wants(&report(vec![]), Path::new(abs)));
        let mut r = report(vec![suspicious("x")]);
        apply(&mut r, &Said::Clean, &[]);
        assert!(!wants(&r, Path::new(abs)), "asked once per report");
    }

    #[test]
    fn status_needs_defender_on_and_in_charge() {
        assert_eq!(parse_status(r#"{"av":true,"mode":"Normal","dir":"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1\\"}"#).as_deref(), Some("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1\\"));
        assert_eq!(parse_status("\u{feff}{\"av\":true}").as_deref(), Some(""), "older Windows: no mode, no folder");
        assert_eq!(parse_status(r#"{"av":true,"mode":"Passive Mode"}"#), None);
        assert_eq!(parse_status(r#"{"av":false,"mode":"Normal"}"#), None);
        assert_eq!(parse_status("{}"), None);
        assert_eq!(parse_status(""), None);
    }

    /// The real Defender, on a Windows machine where it is on: the EICAR test file (built at run
    /// time so this source is not itself detected) is named as a virus. Skipped where Defender is
    /// off or real-time protection takes the file first.
    #[cfg(windows)]
    #[test]
    fn real_defender_names_the_eicar_test_file() {
        let parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"];
        let dir = std::env::temp_dir().join(format!("genra-defender-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("eicar.com");
        if std::fs::write(&p, parts.concat()).is_err() {
            eprintln!("skipped: the test file could not be written (Defender took it)");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        match imp::ask(&p, &"e".repeat(64)) {
            None if !p.exists() => eprintln!("skipped: real-time protection took the test file"),
            None => eprintln!("skipped: Defender is off on this machine"),
            Some((said, _)) => assert!(matches!(&said, Said::Threat(Some(n)) if n.contains("EICAR")), "{said:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
