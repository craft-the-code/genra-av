//! Microsoft Defender as a second opinion (ADR 0004, layer 4).
//!
//! When Genra's own layers call a file *suspicious*, and Defender is this computer's antivirus
//! (on, not in passive mode), Genra asks it about that one file with
//! `MpCmdRun.exe -Scan -ScanType 3 -File <path> -DisableRemediation`: Defender reports, it does
//! not act. A detection in a malware category (Trojan, Backdoor, Worm, Virus, Ransom, PWS,
//! Spyware) makes the finding *malware*, with Defender's own name for it; a detection in another
//! category (hack tools, unwanted software, remote access) is shown but changes nothing.
//!
//! Only programs, scripts, shortcuts, disk images and archives are sent to Defender. Office
//! documents, PDFs and the like are the user's own data, which Defender's sample submission
//! could upload; macros have Genra's own path ("Dọn sạch giúp tôi" keeps the data). Genra sends nothing itself; Defender follows its own settings.
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

/// Kinds of file Defender is asked about: programs, scripts, shortcuts, disk images and
/// archives (the delivery formats). Anything else (PDFs, documents, text) is the user's own data
/// and stays away from Defender's sample submission.
const ASKED: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp", "ocx", "sys", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "bat", "cmd", "lnk",
    "url", "jar", "iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "cab",
];

/// The layer is on unless the pack switched it off.
pub fn enabled(disabled: &[String]) -> bool {
    !disabled.iter().any(|d| d == RULE)
}

/// A `disabled` entry matches a rule id exactly, or as a prefix when it ends with `*`
/// (`defender.Trojan_Win32_Wacatac*` switches off the whole family).
fn switched_off(disabled: &[String], rule: &str) -> bool {
    disabled.iter().any(|d| d == rule || d.strip_suffix('*').is_some_and(|p| p.starts_with("defender.") && rule.starts_with(p)))
}

/// True when Genra would ask Defender about this file: something on it is suspicious, nothing on
/// it already moves it, it is a program, script, shortcut, disk image or archive by name and not
/// an Office file by content, and Defender was not asked yet.
pub fn wants(report: &Report, path: &Path) -> bool {
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    report.verdict == Some(Severity::Suspicious)
        && !report.allowed
        && !report.should_quarantine()
        && ASKED.contains(&ext.as_str())
        // An old-format document renamed to .exe is still the user's document; installers
        // (.msi, .msp) are compound files too. Renamed new-format documents and PDFs are caught
        // by content in [`second_opinion`].
        && (report.kind != genra_av_core::extract::Kind::Ole || matches!(ext.as_str(), "msi" | "msp"))
        && report.vba_modules.is_empty()
        && !report.findings.iter().any(|f| f.rule == RULE || f.rule.starts_with("defender."))
        && path.is_absolute()
}

/// What happened when Genra went to ask Defender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Not a file Defender is asked about, or the layer is off.
    NotAsked,
    /// Defender is not this computer's antivirus (off, passive, missing): stop asking.
    Unavailable,
    /// Answered from this session's memory, without running Defender.
    Remembered,
    /// Defender ran and answered.
    Answered,
    /// Defender ran and gave no answer (error, timeout): a scan stops asking after this.
    Failed,
}

/// Asks Defender when [`wants`] says so and Defender is on, and adds what it said to the report.
/// The outcome lets a caller bound how many files, and how much time, one scan spends on it.
pub fn second_opinion(report: &mut Report, path: &Path, disabled: &[String]) -> Outcome {
    opinion(report, path, disabled, true)
}

/// [`second_opinion`] from this session's memory only: Defender is not run. For files after a
/// scan's budget is spent, which still get an answer Defender already gave.
pub fn remembered_opinion(report: &mut Report, path: &Path, disabled: &[String]) -> Outcome {
    opinion(report, path, disabled, false)
}

/// A Word, Excel or PowerPoint file (new format, by its parts) or a PDF, whatever its name.
fn users_document(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else { return true };
    bytes.starts_with(b"%PDF") || genra_av_core::extract::is_office_package(&bytes)
}

fn opinion(report: &mut Report, path: &Path, disabled: &[String], run: bool) -> Outcome {
    if !enabled(disabled) || !wants(report, path) {
        return Outcome::NotAsked;
    }
    let asked = if run { ask(path, &report.sha256, || users_document(path)) } else { remembered(&report.sha256) };
    let (said, outcome) = match asked {
        Asked::Skipped => return Outcome::NotAsked,
        Asked::Unavailable => return Outcome::Unavailable,
        Asked::Failed => return Outcome::Failed,
        Asked::Said(s, ran) => (s, if ran { Outcome::Answered } else { Outcome::Remembered }),
    };
    apply(report, &said, disabled);
    // Like the signed-file rail: another engine's name alone never moves a validly signed program
    // (Defender's machine-learning names, `!ml`, are the ones most often wrong). It is still shown
    // as malware; the user decides.
    if report.should_quarantine() && report.findings.iter().filter(|f| f.auto_quarantine && f.severity == Severity::Malware).all(|f| f.rule.starts_with("defender.")) && crate::rails::validly_signed(path) {
        for f in report.findings.iter_mut().filter(|f| f.rule.starts_with("defender.")) {
            f.auto_quarantine = false;
        }
        if !report.findings.iter().any(|f| f.rule == "rail.signed_file") {
            report.findings.push(Finding {
                rule: "rail.signed_file".into(),
                family: "signed".into(),
                severity: Severity::Info,
                message_vi: "Tệp có chữ ký số hợp lệ nên Genra không tự cách ly chỉ vì Defender cảnh báo; bạn quyết định.".into(),
                message_en: Some("The file has a valid digital signature, so Genra does not quarantine it on Defender's word alone; you decide.".into()),
                auto_quarantine: false,
            });
        }
    }
    outcome
}

/// Adds Defender's answer to the report and recomputes the verdict.
pub fn apply(report: &mut Report, said: &Said, disabled: &[String]) {
    let f = finding(said);
    if switched_off(disabled, &f.rule) {
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
            // Not "no malware": Defender skips what is in its exclusions, which malware adds.
            message_vi: "Genra đã hỏi thêm Windows Defender: Defender không cảnh báo thêm về tệp này.".into(),
            message_en: Some("Genra also asked Windows Defender: it gave no further warning about this file.".into()),
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
        Some(2) => {
            // The list marker is not translated; names come after it (the "Scanning <path>" line
            // before it holds the file name, which a zip entry could shape like a threat name).
            let list = stdout.find("LIST OF DETECTED THREATS").map(|i| &stdout[i..]).unwrap_or(stdout);
            let names: Vec<&str> = list.split_whitespace().filter_map(threat_name).collect();
            // Several detections: a malware name wins over a HackTool listed first.
            let pick = names.iter().find(|n| is_malware(n)).or(names.first());
            Some(Said::Threat(pick.map(|n| n.to_string())))
        }
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

/// What [`ask`] got.
#[cfg_attr(not(windows), allow(dead_code))]
enum Asked {
    /// The file turned out to be the user's own document: not sent.
    Skipped,
    Unavailable,
    Failed,
    /// The answer, and whether Defender ran for it (false: remembered).
    Said(Said, bool),
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    const STATUS_TTL: Duration = Duration::from_secs(600);
    /// Defender's signatures update several times a day; an answer is not kept longer.
    const ANSWER_TTL: Duration = Duration::from_secs(4 * 3600);
    pub const SCAN_TIMEOUT: Duration = Duration::from_secs(60);

    static STATUS: Mutex<Option<(Instant, Option<PathBuf>)>> = Mutex::new(None);
    /// sha256 → what Defender said, for a few hours: a file asked about during the scan is not
    /// sent again when the user opens it or presses "Dọn sạch giúp tôi".
    static SAID: Mutex<Option<HashMap<String, (Instant, Said)>>> = Mutex::new(None);

    const STATUS_SCRIPT: &str = "$o=@{};\
        try{$m=Get-MpComputerStatus -ErrorAction Stop;$o.av=[bool]$m.AntivirusEnabled;$o.mode=[string]$m.AMRunningMode}catch{};\
        try{$o.dir=[string](Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender' -Name InstallLocation -ErrorAction Stop).InstallLocation}catch{};\
        $o|ConvertTo-Json -Compress";

    /// MpCmdRun.exe when Defender is on; looked up once every ten minutes.
    pub fn mpcmdrun() -> Option<PathBuf> {
        let mut g = STATUS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, p)) = g.as_ref() {
            if at.elapsed() < STATUS_TTL {
                return p.clone();
            }
        }
        let found = crate::proc::powershell(STATUS_SCRIPT, Duration::from_secs(30)).ok().and_then(|o| parse_status(&o.stdout)).and_then(|dir| {
            // The platform folder Defender updates itself into, then the one Windows ships.
            let platform = Some(PathBuf::from(dir).join("MpCmdRun.exe")).filter(|p| p.is_absolute() && p.is_file());
            platform.or_else(|| {
                std::env::var_os("ProgramW6432")
                    .or_else(|| std::env::var_os("ProgramFiles"))
                    .map(|pf| PathBuf::from(pf).join("Windows Defender").join("MpCmdRun.exe"))
                    .filter(|p| p.is_file())
            })
        });
        *g = Some((Instant::now(), found.clone()));
        found
    }

    pub(super) fn remembered(sha256: &str) -> Asked {
        let g = SAID.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_ref().and_then(|m| m.get(sha256)) {
            Some((at, s)) if at.elapsed() < ANSWER_TTL => Asked::Said(s.clone(), false),
            _ => Asked::Skipped,
        }
    }

    pub(super) fn ask(path: &Path, sha256: &str, users_document: impl FnOnce() -> bool) -> Asked {
        if let r @ Asked::Said(..) = remembered(sha256) {
            return r;
        }
        if users_document() {
            return Asked::Skipped;
        }
        let Some(mp) = mpcmdrun() else { return Asked::Unavailable };
        let (Some(mp), Some(file)) = (mp.to_str(), path.to_str()) else { return Asked::Failed };
        let Ok(out) = crate::proc::run(mp, &["-Scan", "-ScanType", "3", "-File", file, "-DisableRemediation"], SCAN_TIMEOUT) else { return Asked::Failed };
        let Some(said) = parse_scan(out.status, &out.stdout) else { return Asked::Failed };
        SAID.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(sha256.to_string(), (Instant::now(), said.clone()));
        Asked::Said(said, true)
    }
}

#[cfg(windows)]
use imp::{ask, remembered};

#[cfg(not(windows))]
fn ask(_path: &Path, _sha256: &str, _users_document: impl FnOnce() -> bool) -> Asked {
    Asked::Unavailable
}

#[cfg(not(windows))]
fn remembered(_sha256: &str) -> Asked {
    Asked::Skipped
}

/// A bounded run of second opinions for one scan: at most [`Budget::FILES`] files, none started
/// after [`Budget::TIME`] (one already running may take its own 60 s timeout), none after Defender failed once or turned out to be off, none once
/// the user pressed "Dừng".
pub struct Budget {
    started: std::time::Instant,
    tried: usize,
    done: bool,
}

impl Budget {
    pub const FILES: usize = 20;
    pub const TIME: std::time::Duration = std::time::Duration::from_secs(120);

    pub fn new() -> Budget {
        Budget { started: std::time::Instant::now(), tried: 0, done: false }
    }

    /// Whether the next file may be sent to Defender.
    pub fn open(&self, stop: Option<&std::sync::atomic::AtomicBool>) -> bool {
        !self.done && self.tried < Self::FILES && self.started.elapsed() < Self::TIME && !stop.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed))
    }

    pub fn record(&mut self, o: Outcome) {
        match o {
            Outcome::Answered => self.tried += 1,
            Outcome::Failed | Outcome::Unavailable => {
                self.tried += 1;
                self.done = true;
            }
            Outcome::NotAsked | Outcome::Remembered => {}
        }
    }
}

impl Default for Budget {
    fn default() -> Self {
        Budget::new()
    }
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
        let two = "LIST OF DETECTED THREATS\nThreat : HackTool:Win32/Mimikatz\nThreat : Trojan:Win32/Wacatac.B!ml";
        assert_eq!(parse_scan(Some(2), two), Some(Said::Threat(Some("Trojan:Win32/Wacatac.B!ml".into()))), "malware wins");
        let shaped = "Scanning C:\\a.zip->Trojan:Win32/Fake.A found 1 threats.\nLIST OF DETECTED THREATS\nThreat : PUA:Win32/Presenoker";
        assert_eq!(parse_scan(Some(2), shaped), Some(Said::Threat(Some("PUA:Win32/Presenoker".into()))), "names before the list are not read");
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
        assert_eq!(second_opinion(&mut r, Path::new("C:\\a.js"), &["defender".into()]), Outcome::NotAsked);
        assert_eq!(r.findings.len(), 1);
        let mut r = report(vec![suspicious("x")]);
        apply(&mut r, &Said::Threat(Some(name.into())), &["defender.Trojan_Win32_Wacatac*".into()]);
        assert_eq!(r.verdict, Some(Severity::Suspicious), "a family switched off by prefix");
        let mut r = report(vec![suspicious("x")]);
        apply(&mut r, &Said::Threat(Some(name.into())), &["defender.Trojan_Win32_Other*".into()]);
        assert_eq!(r.verdict, Some(Severity::Malware));
    }

    #[test]
    fn asks_only_about_suspicious_files_that_are_not_office_documents() {
        let abs = if cfg!(windows) { "C:\\Users\\An\\a.js" } else { "/home/an/a.js" };
        assert!(wants(&report(vec![suspicious("x")]), Path::new(abs)));
        assert!(!wants(&report(vec![suspicious("x")]), Path::new("a.js")), "relative path");
        let at = |n: &str| if cfg!(windows) { format!("C:\\Users\\An\\{n}") } else { format!("/home/an/{n}") };
        for kept in ["a.xlsm", "a.pdf", "a.docx", "hoa-don", "a.txt"] {
            assert!(!wants(&report(vec![suspicious("x")]), Path::new(&at(kept))), "{kept}: the user's own data");
        }
        for asked in ["a.exe", "a.lnk", "a.ps1", "a.zip", "a.iso"] {
            assert!(wants(&report(vec![suspicious("x")]), Path::new(&at(asked))), "{asked}");
        }
        let mut msi = report(vec![suspicious("x")]);
        msi.kind = genra_av_core::extract::Kind::Ole;
        assert!(wants(&msi, Path::new(&at("setup.msi"))), "installers are compound files too");
        let mut renamed = report(vec![suspicious("x")]);
        renamed.kind = genra_av_core::extract::Kind::Ole;
        assert!(!wants(&renamed, Path::new(&at("bao-cao.exe"))), "a document renamed to .exe");
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

    #[test]
    fn renamed_pdfs_and_new_format_documents_are_found_by_content() {
        let dir = std::env::temp_dir().join(format!("genra-defender-doc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pdf = dir.join("hoa-don.exe");
        std::fs::write(&pdf, b"%PDF-1.7\n...").unwrap();
        assert!(users_document(&pdf));
        let docx = dir.join("bao-cao.zip");
        {
            use std::io::Write;
            let mut z = zip::ZipWriter::new(std::fs::File::create(&docx).unwrap());
            let o = zip::write::SimpleFileOptions::default();
            for (n, b) in [("[Content_Types].xml", &b"<Types/>"[..]), ("word/document.xml", b"<w:document/>")] {
                z.start_file(n, o).unwrap();
                z.write_all(b).unwrap();
            }
            z.finish().unwrap();
        }
        assert!(users_document(&docx));
        let prog = dir.join("setup.exe");
        std::fs::write(&prog, b"MZ\x90\x00").unwrap();
        assert!(!users_document(&prog));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scan_stops_asking_after_a_failure_the_cap_or_stop() {
        let mut b = Budget::new();
        for _ in 0..Budget::FILES {
            assert!(b.open(None));
            b.record(Outcome::Answered);
        }
        assert!(!b.open(None), "cap reached");
        let mut b = Budget::new();
        b.record(Outcome::Remembered);
        b.record(Outcome::NotAsked);
        assert!(b.open(None), "remembered answers cost nothing");
        b.record(Outcome::Failed);
        assert!(!b.open(None), "one timeout or error ends the asking");
        let stop = std::sync::atomic::AtomicBool::new(true);
        assert!(!Budget::new().open(Some(&stop)), "the user pressed Dừng");
    }

    /// The real Defender, on a Windows machine where it is on: the EICAR test file (built at run
    /// time so this source is not itself detected) is named as a virus. Skipped (and said so in
    /// the output) only where Defender is off or real-time protection takes the file first.
    #[cfg(windows)]
    #[test]
    fn real_defender_names_the_eicar_test_file() {
        let Some(mp) = imp::mpcmdrun() else {
            println!("skipped: Defender is not this machine's antivirus");
            return;
        };
        let parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"];
        let dir = std::env::temp_dir().join(format!("genra-defender-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("eicar.com");
        let written = std::fs::write(&p, parts.concat()).is_ok();
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !written || !p.exists() {
            println!("skipped: real-time protection took the test file");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let got = imp::ask(&p, &"e".repeat(64), || false);
        let gone = !p.exists();
        let _ = std::fs::remove_dir_all(&dir);
        match got {
            Asked::Said(Said::Threat(Some(n)), true) => {
                assert!(n.contains("EICAR"), "{n}");
                println!("Defender ({}) named the test file {n}", mp.display());
            }
            Asked::Said(said, _) => panic!("Defender answered {said:?} for the EICAR file"),
            _ if gone => println!("skipped: real-time protection took the test file during the scan"),
            _ => panic!("Defender is on ({}) but gave no answer for the EICAR file", mp.display()),
        }
    }
}
