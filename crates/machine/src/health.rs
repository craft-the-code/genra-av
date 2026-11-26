//! One line per thing that keeps the machine safe: the built-in antivirus, updates, the
//! firewall, and Office's macro setting. Genra reads these and never turns protection off;
//! the only fix in v0.1 is resetting Office's "enable all macros" through the journal.
//!
//! Windows reads everything in one hidden PowerShell call (`Get-MpComputerStatus`,
//! `Get-HotFix`, `Get-NetFirewallProfile`) plus the registry; macOS uses `spctl`,
//! `socketfilterfw`, XProtect's bundle and the install history. A check that cannot be read is
//! `Unknown`, never a guess.

use crate::journal::Journal;
use crate::repair::{self, Action, MacroLevel, OfficeApp, Plan, RunReport, Step};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Warn,
    Bad,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixId {
    OfficeMacroPolicy,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthItem {
    pub id: String,
    pub status: Status,
    pub title_vi: String,
    pub title_en: String,
    pub detail_vi: String,
    pub detail_en: String,
    pub fix: Option<FixId>,
}

fn item(id: &str, status: Status, title: (&str, &str), detail: (String, String)) -> HealthItem {
    HealthItem { id: id.into(), status, title_vi: title.0.into(), title_en: title.1.into(), detail_vi: detail.0, detail_en: detail.1, fix: None }
}

fn unknown(id: &str, title: (&str, &str)) -> HealthItem {
    item(id, Status::Unknown, title, ("Genra chưa đọc được mục này trên máy.".into(), "Genra could not read this on this computer.".into()))
}

pub fn check() -> Vec<HealthItem> {
    imp::check()
}

/// Applies a fix through the journal, as one repair the user can undo.
pub fn fix(id: FixId, journal: &mut Journal) -> Result<RunReport> {
    match id {
        FixId::OfficeMacroPolicy => {
            let steps = [OfficeApp::Excel, OfficeApp::Word, OfficeApp::PowerPoint]
                .into_iter()
                .map(|app| Step {
                    action: Action::SetOfficeMacroPolicy { app, level: MacroLevel::DisableWithNotification },
                    title_vi: format!("Tắt tự chạy macro trong {}", app.key_name()),
                    title_en: format!("Stop {} running macros on its own", app.key_name()),
                    needs: None,
                })
                .collect();
            let plan = Plan {
                group_id: Journal::new_group_id()?,
                steps,
                summary_vi: "Đặt lại cài đặt macro của Office về mặc định an toàn".into(),
                summary_en: "Reset Office's macro setting to the safe default".into(),
            };
            Ok(repair::run_in(&plan, journal, Default::default, |_| {}))
        }
    }
}

// ---- Windows ----

/// Reads the JSON the Windows health script prints:
/// `{"defender":{"rtp":true,"av":true,"age":1},"hotfix_days":12,"firewall":[{"name":"Domain","enabled":"True"}]}`.
pub fn parse_windows_health(text: &str) -> Vec<HealthItem> {
    let v: serde_json::Value = serde_json::from_str(text.trim().trim_start_matches('\u{feff}')).unwrap_or_default();
    let mut out = Vec::new();
    let truthy = |x: &serde_json::Value| match x {
        serde_json::Value::Bool(b) => Some(*b),
        serde_json::Value::Number(n) => n.as_i64().map(|n| n != 0),
        serde_json::Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    };

    let t_def = ("Windows Defender", "Windows Defender");
    let t_sig = ("Mẫu nhận diện của Defender", "Defender's virus definitions");
    match v.get("defender") {
        Some(d) if d.is_object() => {
            let rtp = d.get("rtp").and_then(truthy);
            let av = d.get("av").and_then(truthy);
            out.push(match (av, rtp) {
                (Some(true), Some(true)) => item("defender", Status::Ok, t_def, ("Đang bật và bảo vệ máy liên tục.".into(), "On, protecting the computer all the time.".into())),
                (Some(true), Some(false)) => item(
                    "defender",
                    Status::Bad,
                    t_def,
                    (
                        "Bảo vệ thời gian thực đang tắt: máy không được canh chừng liên tục. Mở Bảo mật Windows, chọn “Bảo vệ khỏi vi-rút và mối đe dọa” rồi bật lại.".into(),
                        "Real-time protection is off: the computer is not watched all the time. Open Windows Security, choose “Virus & threat protection” and turn it back on.".into(),
                    ),
                ),
                (Some(false), _) => item(
                    "defender",
                    Status::Warn,
                    t_def,
                    (
                        "Defender không chạy. Nếu máy đã có phần mềm diệt virus khác thì không sao; nếu không, mở Bảo mật Windows để bật lại.".into(),
                        "Defender is not running. That is fine if another antivirus is installed; if not, open Windows Security to turn it back on.".into(),
                    ),
                ),
                _ => unknown("defender", t_def),
            });
            match d.get("age").and_then(|a| a.as_i64()) {
                Some(age) if (0..=7).contains(&age) => out.push(item("defender_signatures", Status::Ok, t_sig, (format!("Cập nhật {age} ngày trước."), format!("Updated {age} day(s) ago.")))),
                Some(age) if age > 7 => out.push(item(
                    "defender_signatures",
                    Status::Warn,
                    t_sig,
                    (
                        format!("Đã {age} ngày chưa cập nhật, nên Defender có thể không nhận ra mã độc mới. Nối mạng và mở Windows Update."),
                        format!("Not updated for {age} days, so Defender may miss new malware. Connect to the internet and open Windows Update."),
                    ),
                )),
                _ => out.push(unknown("defender_signatures", t_sig)),
            }
        }
        _ => {
            out.push(item(
                "defender",
                Status::Unknown,
                t_def,
                (
                    "Genra không đọc được trạng thái Defender. Máy có thể đang dùng phần mềm diệt virus khác.".into(),
                    "Genra could not read Defender's state. The computer may be using another antivirus.".into(),
                ),
            ));
        }
    }

    let t_upd = ("Cập nhật Windows", "Windows updates");
    out.push(match v.get("hotfix_days").and_then(|d| d.as_i64()) {
        Some(d) if (0..=45).contains(&d) => item("updates", Status::Ok, t_upd, (format!("Bản cập nhật gần nhất cài {d} ngày trước."), format!("The last update was installed {d} day(s) ago."))),
        Some(d) if d > 45 => item(
            "updates",
            Status::Warn,
            t_upd,
            (
                format!("Đã {d} ngày máy chưa cài bản cập nhật nào. Mở Windows Update và bấm “Kiểm tra bản cập nhật”."),
                format!("No update has been installed for {d} days. Open Windows Update and press “Check for updates”."),
            ),
        ),
        _ => unknown("updates", t_upd),
    });

    let t_fw = ("Tường lửa", "Firewall");
    let profiles: Vec<(String, Option<bool>)> = match v.get("firewall") {
        Some(serde_json::Value::Array(a)) => a.iter().map(|p| (p.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(), p.get("enabled").and_then(truthy))).collect(),
        Some(p @ serde_json::Value::Object(_)) => vec![(p.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(), p.get("enabled").and_then(truthy))],
        _ => Vec::new(),
    };
    let off: Vec<&str> = profiles.iter().filter(|(_, e)| *e == Some(false)).map(|(n, _)| n.as_str()).collect();
    out.push(if profiles.is_empty() || profiles.iter().any(|(_, e)| e.is_none()) && off.is_empty() {
        unknown("firewall", t_fw)
    } else if off.is_empty() {
        item("firewall", Status::Ok, t_fw, ("Đang bật cho mọi loại mạng.".into(), "On for every kind of network.".into()))
    } else {
        item(
            "firewall",
            Status::Warn,
            t_fw,
            (
                format!("Đang tắt cho mạng {}. Mở Bảo mật Windows, chọn “Tường lửa và bảo vệ mạng” rồi bật lại.", off.join(", ")),
                format!("Off for the {} network(s). Open Windows Security, choose “Firewall & network protection” and turn it back on.", off.join(", ")),
            ),
        )
    });
    out
}

/// The Office macro line from each app's `VBAWarnings` values (`None` = not set, Office's
/// default "disable with notification"). `None` overall when Office is not set up.
pub fn macro_item(settings: &[(OfficeApp, Option<u32>)]) -> Option<HealthItem> {
    if settings.is_empty() {
        return None;
    }
    let t = ("Cài đặt macro của Office", "Office macro setting");
    let mut open: Vec<&str> = settings.iter().filter(|(_, v)| *v == Some(1)).map(|(a, _)| a.key_name()).collect();
    open.dedup();
    if open.is_empty() {
        return Some(item("office_macros", Status::Ok, t, ("Office không tự chạy macro; tệp có macro sẽ hỏi bạn trước.".into(), "Office does not run macros on its own; a file with macros asks you first.".into())));
    }
    let mut i = item(
        "office_macros",
        Status::Warn,
        t,
        (
            format!("{} đang để “bật mọi macro”: mở một tệp nhiễm sâu là sâu chạy ngay. Bấm “Sửa giúp tôi” để đưa về mặc định an toàn (có thể hoàn tác).", open.join(", ")),
            format!("{} is set to “enable all macros”: opening an infected file runs the worm at once. Press “Fix it for me” to restore the safe default (can be undone).", open.join(", ")),
        ),
    );
    i.fix = Some(FixId::OfficeMacroPolicy);
    Some(i)
}

// ---- macOS ----

/// `spctl --status`: "assessments enabled" / "assessments disabled".
pub fn parse_spctl(out: &str) -> Option<bool> {
    let o = out.to_ascii_lowercase();
    if o.contains("assessments enabled") {
        Some(true)
    } else if o.contains("assessments disabled") {
        Some(false)
    } else {
        None
    }
}

/// `socketfilterfw --getglobalstate`: "Firewall is enabled. (State = 1)" / "... disabled ...".
pub fn parse_socketfilterfw(out: &str) -> Option<bool> {
    let o = out.to_ascii_lowercase();
    if o.contains("enabled") || o.contains("state = 1") || o.contains("state = 2") {
        Some(true)
    } else if o.contains("disabled") || o.contains("state = 0") {
        Some(false)
    } else {
        None
    }
}

/// Days since the newest install done by Software Update in `/Library/Receipts/InstallHistory.plist`.
pub fn days_since_last_update(plist_bytes: &[u8], now: std::time::SystemTime) -> Option<u64> {
    let v = plist::Value::from_reader(std::io::Cursor::new(plist_bytes)).ok()?;
    let newest = v
        .as_array()?
        .iter()
        .filter_map(|e| e.as_dictionary())
        .filter(|d| d.get("processName").and_then(|p| p.as_string()).is_some_and(|p| p.eq_ignore_ascii_case("softwareupdated")))
        .filter_map(|d| d.get("date").and_then(|x| x.as_date()).map(std::time::SystemTime::from))
        .max()?;
    Some(now.duration_since(newest).map(|d| d.as_secs() / 86_400).unwrap_or(0))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn mac_items(spctl: Option<bool>, firewall: Option<bool>, xprotect: Option<String>, update_days: Option<u64>) -> Vec<HealthItem> {
    let t_gk = ("Gatekeeper", "Gatekeeper");
    let t_xp = ("XProtect", "XProtect");
    let t_fw = ("Tường lửa", "Firewall");
    let t_up = ("Cập nhật macOS", "macOS updates");
    vec![
        match spctl {
            Some(true) => item("gatekeeper", Status::Ok, t_gk, ("Đang bật: macOS kiểm tra ứng dụng trước khi mở.".into(), "On: macOS checks apps before opening them.".into())),
            Some(false) => item(
                "gatekeeper",
                Status::Bad,
                t_gk,
                (
                    "Đang tắt: ứng dụng lạ mở được mà không bị kiểm tra. Nhờ người quản lý máy bật lại (cần quyền quản trị).".into(),
                    "Off: unknown apps open without being checked. Ask whoever manages this Mac to turn it back on (needs admin rights).".into(),
                ),
            ),
            None => unknown("gatekeeper", t_gk),
        },
        match xprotect {
            Some(ver) => item("xprotect", Status::Ok, t_xp, (format!("Bộ nhận diện mã độc có sẵn của macOS (phiên bản {ver})."), format!("macOS's built-in malware detection (version {ver})."))),
            None => unknown("xprotect", t_xp),
        },
        match firewall {
            Some(true) => item("firewall", Status::Ok, t_fw, ("Đang bật.".into(), "On.".into())),
            Some(false) => item(
                "firewall",
                Status::Warn,
                t_fw,
                (
                    "Đang tắt (mặc định của macOS). Nên bật trong Cài đặt hệ thống > Mạng > Tường lửa, nhất là khi dùng Wi-Fi công cộng.".into(),
                    "Off (macOS's default). Turn it on in System Settings > Network > Firewall, especially on public Wi-Fi.".into(),
                ),
            ),
            None => unknown("firewall", t_fw),
        },
        match update_days {
            Some(d) if d <= 45 => item("updates", Status::Ok, t_up, (format!("Bản cập nhật gần nhất cài {d} ngày trước."), format!("The last update was installed {d} day(s) ago."))),
            Some(d) => item(
                "updates",
                Status::Warn,
                t_up,
                (
                    format!("Đã {d} ngày máy chưa cài bản cập nhật nào. Mở Cài đặt hệ thống > Cài đặt chung > Cập nhật phần mềm."),
                    format!("No update has been installed for {d} days. Open System Settings > General > Software Update."),
                ),
            ),
            None => unknown("updates", t_up),
        },
    ]
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::time::Duration;

    const SCRIPT: &str = "$o=@{};\
        try{$m=Get-MpComputerStatus -ErrorAction Stop;$o.defender=@{rtp=[bool]$m.RealTimeProtectionEnabled;av=[bool]$m.AntivirusEnabled;age=[int]$m.AntivirusSignatureAge}}catch{};\
        try{$h=Get-HotFix -ErrorAction Stop|Where-Object{$_.InstalledOn}|Sort-Object InstalledOn -Descending|Select-Object -First 1;if($h){$o.hotfix_days=[int][math]::Floor(((Get-Date)-$h.InstalledOn).TotalDays)}}catch{};\
        try{$o.firewall=@(Get-NetFirewallProfile -ErrorAction Stop|ForEach-Object{@{name=[string]$_.Name;enabled=[string]$_.Enabled}})}catch{};\
        $o|ConvertTo-Json -Depth 4 -Compress";

    pub fn check() -> Vec<HealthItem> {
        let mut out = match crate::proc::powershell(SCRIPT, Duration::from_secs(40)) {
            Ok(o) => parse_windows_health(&o.stdout),
            Err(_) => parse_windows_health("{}"),
        };
        let settings: Vec<(OfficeApp, Option<u32>)> = [OfficeApp::Excel, OfficeApp::Word, OfficeApp::PowerPoint]
            .into_iter()
            .flat_map(|app| repair::macro_settings(app).into_iter().map(move |(_, v)| (app, v)))
            .collect();
        out.extend(macro_item(&settings));
        out
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::proc::run;
    use std::time::Duration;

    pub fn check() -> Vec<HealthItem> {
        let spctl = run("/usr/sbin/spctl", &["--status"], Duration::from_secs(10)).ok().and_then(|o| parse_spctl(&format!("{}{}", o.stdout, o.stderr)));
        let fw = run("/usr/libexec/ApplicationFirewall/socketfilterfw", &["--getglobalstate"], Duration::from_secs(10)).ok().and_then(|o| parse_socketfilterfw(&o.stdout));
        let xp = std::fs::read("/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist")
            .ok()
            .and_then(|b| plist::Value::from_reader(std::io::Cursor::new(b)).ok())
            .and_then(|v| v.as_dictionary().and_then(|d| d.get("CFBundleShortVersionString")).and_then(|s| s.as_string()).map(String::from));
        let upd = std::fs::read("/Library/Receipts/InstallHistory.plist").ok().and_then(|b| days_since_last_update(&b, std::time::SystemTime::now()));
        mac_items(spctl, fw, xp, upd)
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use super::*;
    pub fn check() -> Vec<HealthItem> {
        vec![unknown("antivirus", ("Phần mềm diệt virus", "Antivirus")), unknown("updates", ("Cập nhật hệ thống", "System updates")), unknown("firewall", ("Tường lửa", "Firewall"))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn by_id<'a>(v: &'a [HealthItem], id: &str) -> &'a HealthItem {
        v.iter().find(|i| i.id == id).unwrap_or_else(|| panic!("no {id}"))
    }

    #[test]
    fn windows_all_good() {
        let v = parse_windows_health(r#"{"defender":{"rtp":true,"av":true,"age":1},"hotfix_days":12,"firewall":[{"name":"Domain","enabled":"True"},{"name":"Private","enabled":"True"},{"name":"Public","enabled":"True"}]}"#);
        assert!(v.iter().all(|i| i.status == Status::Ok), "{v:#?}");
        assert_eq!(v.len(), 4);
    }

    #[test]
    fn windows_problems() {
        let v = parse_windows_health("\u{feff}{\"defender\":{\"rtp\":false,\"av\":true,\"age\":30},\"hotfix_days\":120,\"firewall\":{\"name\":\"Public\",\"enabled\":0}}");
        assert_eq!(by_id(&v, "defender").status, Status::Bad);
        assert_eq!(by_id(&v, "defender_signatures").status, Status::Warn);
        assert!(by_id(&v, "defender_signatures").detail_vi.contains("30 ngày"));
        assert_eq!(by_id(&v, "updates").status, Status::Warn);
        let fw = by_id(&v, "firewall");
        assert_eq!(fw.status, Status::Warn);
        assert!(fw.detail_en.contains("Public"));
    }

    #[test]
    fn windows_unreadable_is_unknown() {
        for text in ["", "{}", "not json", r#"{"firewall":[{"name":"Domain","enabled":"NotConfigured"}]}"#] {
            let v = parse_windows_health(text);
            assert!(v.iter().all(|i| i.status == Status::Unknown), "{text}: {v:#?}");
        }
        let v = parse_windows_health(r#"{"defender":{"rtp":false,"av":false,"age":3}}"#);
        assert_eq!(by_id(&v, "defender").status, Status::Warn, "another antivirus may be in charge");
    }

    #[test]
    fn macro_setting() {
        assert!(macro_item(&[]).is_none());
        let ok = macro_item(&[(OfficeApp::Excel, None), (OfficeApp::Word, Some(2))]).unwrap();
        assert_eq!((ok.status, ok.fix), (Status::Ok, None));
        let w = macro_item(&[(OfficeApp::Excel, Some(1)), (OfficeApp::Excel, Some(1)), (OfficeApp::Word, Some(4))]).unwrap();
        assert_eq!((w.status, w.fix), (Status::Warn, Some(FixId::OfficeMacroPolicy)));
        assert!(w.detail_vi.starts_with("Excel đang") && !w.detail_vi.contains("Word"));
    }

    #[test]
    fn mac_parsers() {
        assert_eq!(parse_spctl("assessments enabled\n"), Some(true));
        assert_eq!(parse_spctl("assessments disabled\n"), Some(false));
        assert_eq!(parse_spctl(""), None);
        assert_eq!(parse_socketfilterfw("Firewall is enabled. (State = 1)\n"), Some(true));
        assert_eq!(parse_socketfilterfw("Firewall is disabled. (State = 0)\n"), Some(false));
        assert_eq!(parse_socketfilterfw("weird"), None);
        let items = mac_items(Some(true), Some(false), Some("5300".into()), Some(80));
        assert_eq!(items.iter().map(|i| i.status).collect::<Vec<_>>(), [Status::Ok, Status::Ok, Status::Warn, Status::Warn]);
    }

    #[test]
    fn install_history() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array>
<dict><key>date</key><date>2026-10-01T10:00:00Z</date><key>displayName</key><string>macOS 27.1</string><key>processName</key><string>softwareupdated</string></dict>
<dict><key>date</key><date>2026-11-20T10:00:00Z</date><key>displayName</key><string>XProtectPlistConfigData</string><key>processName</key><string>softwareupdated</string></dict>
<dict><key>date</key><date>2026-11-25T10:00:00Z</date><key>displayName</key><string>Some App</string><key>processName</key><string>installer</string></dict>
</array></plist>"#;
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_795_651_200); // 2026-11-26T00:00:00Z
        assert_eq!(days_since_last_update(xml, now), Some(5));
        assert_eq!(days_since_last_update(b"<plist><array/></plist>", now), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn the_macro_fix_is_not_applicable_off_windows() {
        let root = std::env::temp_dir().join(format!("genra-machine-h-{}", std::process::id()));
        let mut j = Journal::open(&root).unwrap();
        let r = fix(FixId::OfficeMacroPolicy, &mut j).unwrap();
        assert_eq!(r.outcome, repair::Outcome::Done);
        assert!(r.steps.iter().all(|s| s.state == repair::StepState::Skipped));
        let _ = std::fs::remove_dir_all(&root);
    }
}
