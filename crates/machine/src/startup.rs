//! What starts with the machine, and which of those look wrong.
//!
//! - Windows: HKCU/HKLM `Run` and `RunOnce`, the user and common Startup folders, XLSTART, and
//!   scheduled tasks outside `\Microsoft\` (best effort, `schtasks /query /fo csv /v`).
//!   Signatures and shortcut targets come from one hidden PowerShell call per batch.
//! - macOS: `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` (read
//!   only), Excel's startup folder; signatures from `codesign -dv`. Login Items are not listed:
//!   reading them needs System Events automation (a permission prompt) or admin rights.
//! - Linux: `~/.config/autostart` and `/etc/xdg/autostart`.
//!
//! Verdict: **Bad** when the target file matches the rules (scanned with genra-av-core when it is
//! a readable file of at most 100 MB); **Warn** when it is unsigned and sits in AppData, Temp or
//! Downloads (or looks suspicious to the scanner); otherwise Ok or Unknown.

use crate::journal::Journal;
use crate::proc;
use anyhow::{bail, Context, Result};
use genra_av_core::reputation::Reputation;
use genra_av_core::rules::{Pack, Severity};
use genra_av_core::scanner;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemScope {
    /// This user's: Genra can switch it off.
    User,
    /// The whole machine's: changing it needs admin rights, which Genra never asks for.
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Ok,
    Unknown,
    Warn,
    Bad,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupItem {
    /// Stable id, passed to `Action::DisableStartupItem`.
    pub id: String,
    pub name: String,
    /// Where it is registered, e.g. `HKCU\...\Run`, `~/Library/LaunchAgents`.
    pub location: String,
    pub command: String,
    pub scope: ItemScope,
    pub signed: Option<bool>,
    pub publisher: Option<String>,
    pub verdict: Verdict,
    pub reason_vi: String,
    pub reason_en: String,
}

/// How an item is switched off.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
enum Handle {
    /// A registry value (Windows Run / RunOnce).
    RegValue { key: String, name: String },
    /// A file whose presence starts something: Startup-folder shortcut, LaunchAgent plist,
    /// autostart .desktop file, XLSTART workbook.
    File(PathBuf),
    /// A scheduled task (by its full name): listed here; switched off only when it is traced to
    /// a threat ([`disable_task`]).
    Task { name: String },
    /// Listed only (launch daemons).
    #[cfg_attr(windows, allow(dead_code))]
    ReadOnly,
}

#[derive(Debug, Clone)]
struct Raw {
    id: String,
    name: String,
    location: String,
    command: String,
    scope: ItemScope,
    /// The program (or file) that runs.
    target: Option<PathBuf>,
    handle: Handle,
    /// An Excel startup workbook: judged by its macros, not by a signature.
    xlstart: bool,
}

pub fn list() -> Vec<StartupItem> {
    list_with(None, None)
}

/// [`list`] with the rule pack and hash lists to judge targets with.
pub fn list_with(pack: Option<&Pack>, reputation: Option<&Reputation>) -> Vec<StartupItem> {
    let raws = gather();
    let sigs = signatures(&raws);
    let mut items: Vec<StartupItem> = raws.iter().map(|r| judge(r, sigs.get(&r.id), pack, reputation)).collect();
    items.sort_by(|a, b| b.verdict.cmp(&a.verdict).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    items
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Sig {
    pub signed: Option<bool>,
    pub publisher: Option<String>,
    /// A shortcut's target, when the item is a .lnk.
    pub resolved: Option<PathBuf>,
}

/// AppData, Temp, Downloads (and their macOS / Linux equivalents): where real software rarely
/// installs a startup program unsigned, and where droppers put theirs.
pub fn risky_location(path: &Path) -> bool {
    let p = path.to_string_lossy().replace('\\', "/").to_lowercase();
    ["/appdata/", "/temp/", "/tmp/", "/downloads/", "/users/shared/", "/library/application support/", "/.cache/", "/.local/share/"].iter().any(|k| p.contains(k))
}

fn system_location(path: &Path) -> bool {
    let p = path.to_string_lossy().replace('\\', "/").to_lowercase();
    ["/system/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/", "c:/windows/", "c:/program files/", "c:/program files (x86)/"].iter().any(|k| p.starts_with(k))
}

/// A command line safe to show on screen and in screenshots: values after `--token`,
/// `--password` and the like, and long key-looking words, become `…`.
pub fn mask_secrets(cmd: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut hide_next = false;
    for w in cmd.split(' ') {
        let lw = w.to_ascii_lowercase();
        let flag = lw.trim_start_matches('-');
        let secret_flag = lw.starts_with('-') && ["token", "password", "passwd", "secret", "key", "apikey", "api-key", "auth"].iter().any(|k| flag == *k || flag.starts_with(&format!("{k}=")));
        let keyish = w.len() >= 40 && w.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=_-.".contains(&b)) && !w.contains('/');
        if hide_next || keyish {
            out.push("…".into());
        } else if secret_flag && w.contains('=') {
            out.push(format!("{}=…", w.split('=').next().unwrap_or("")));
        } else {
            out.push(w.to_string());
        }
        hide_next = secret_flag && !w.contains('=');
    }
    out.join(" ")
}

fn judge(r: &Raw, sig: Option<&Sig>, pack: Option<&Pack>, rep: Option<&Reputation>) -> StartupItem {
    let target = sig.and_then(|s| s.resolved.clone()).or_else(|| r.target.clone());
    let (signed, publisher) = sig.map(|s| (s.signed, s.publisher.clone())).unwrap_or((None, None));
    let scanned = target.as_deref().and_then(|t| {
        let md = std::fs::metadata(t).ok()?;
        if !md.is_file() || md.len() > scanner::MAX_FILE {
            return None;
        }
        std::fs::read(t).ok().map(|b| genra_av_core::scan_named(&t.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), &b, pack, rep))
    });
    let (verdict, vi, en): (Verdict, String, String) = if let Some(rep) = scanned.as_ref().filter(|s| s.should_quarantine() || s.verdict == Some(Severity::Malware)) {
        let fam = rep.findings.iter().max_by_key(|f| f.severity).map(|f| f.family.clone()).unwrap_or_default();
        (Verdict::Bad, format!("Chương trình này khớp mã độc đã biết ({fam}). Nên tắt nó."), format!("This program matches known malware ({fam}). Switch it off."))
    } else if r.xlstart {
        let f = scanned.as_ref().map(|s| !s.vba_modules.is_empty() || s.findings.iter().any(|f| f.rule == "builtin.vba_unreadable")).unwrap_or(false);
        if f {
            (Verdict::Warn, "Excel tự mở sổ này mỗi lần chạy, và sổ có macro. Nếu bạn không tự đặt nó ở đây, nên gỡ.".into(), "Excel opens this workbook every time it starts, and it has macros. If you did not put it here yourself, remove it.".into())
        } else {
            (Verdict::Ok, "Excel tự mở sổ này mỗi lần chạy; sổ không có macro.".into(), "Excel opens this workbook at start; it has no macros.".into())
        }
    } else if scanned.as_ref().is_some_and(|s| s.verdict.is_some_and(|v| v >= Severity::Suspicious)) {
        (Verdict::Warn, "Genra thấy dấu hiệu đáng ngờ trong chương trình này.".into(), "Genra sees suspicious signs in this program.".into())
    } else if signed == Some(false) && target.as_deref().is_some_and(risky_location) {
        (
            Verdict::Warn,
            "Chương trình không có chữ ký và nằm trong thư mục tạm, tải về hoặc AppData. Nếu bạn không biết nó, nên tắt.".into(),
            "The program is unsigned and sits in a temporary, Downloads or AppData folder. If you do not know it, switch it off.".into(),
        )
    } else if signed == Some(true) {
        let who = publisher.clone().map(|p| format!(" ({p})")).unwrap_or_default();
        (Verdict::Ok, format!("Chương trình có chữ ký của nhà phát hành{who}."), format!("The program is signed by its publisher{who}."))
    } else if target.as_deref().is_some_and(|t| t.exists() && system_location(t)) {
        (Verdict::Ok, "Chương trình của hệ thống.".into(), "A system program.".into())
    } else if target.as_deref().is_some_and(|t| !t.exists()) {
        (Verdict::Unknown, "Không tìm thấy chương trình mà mục này chạy.".into(), "The program this item runs was not found.".into())
    } else {
        (Verdict::Unknown, "Genra chưa đủ thông tin để đánh giá mục này.".into(), "Genra does not know enough to judge this item.".into())
    };
    StartupItem { id: r.id.clone(), name: r.name.clone(), location: r.location.clone(), command: mask_secrets(&r.command), scope: r.scope, signed, publisher, verdict, reason_vi: vi, reason_en: en }
}

/// Switches a startup item off through the journal. Returns what to tell the user.
pub(crate) fn disable(id: &str, group: &str, j: &mut Journal) -> Result<(String, String)> {
    let r = find(id).with_context(|| format!("startup item {id} not found (already gone?)"))?;
    if r.scope == ItemScope::System {
        bail!("cần quyền quản trị: {} is set for the whole computer; Genra does not change it", r.name);
    }
    match &r.handle {
        Handle::RegValue { key, name } => {
            let sub = key.rsplit('\\').next().unwrap_or("Run");
            // One backup key per repair: the same value switched off again after a reinfection
            // never collides with the earlier backup.
            let backup = format!("HKCU\\Software\\Genra AV\\DisabledStartup\\{group}\\{sub}");
            j.move_registry_value(group, key, name, &backup, &format!("Tắt “{}” khi khởi động máy", r.name), &format!("Stop “{}” starting with the computer", r.name))?;
        }
        Handle::File(path) => {
            let md = std::fs::symlink_metadata(path)?;
            if !md.is_file() {
                bail!("{} is not a regular file", path.display());
            }
            let bytes = std::fs::read(path)?;
            j.quarantine_file(
                group,
                path,
                &crate::sha256_hex(&bytes),
                "Tắt mục khởi động / startup item switched off",
                &format!("Tắt “{}” khi khởi động máy", r.name),
                &format!("Stop “{}” starting with the computer", r.name),
            )?;
        }
        Handle::Task { .. } | Handle::ReadOnly => bail!("Genra cannot switch this item off yet ({})", r.location),
    }
    Ok((
        format!("“{}” sẽ không tự chạy từ lần mở máy sau. Bấm “Hoàn tác” để bật lại.", r.name),
        format!("“{}” will not start on its own from the next sign-in. Press “Undo” to turn it back on.", r.name),
    ))
}

/// How an entry that starts a threat is switched off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistKind {
    /// A Run/RunOnce value or a Startup-folder file: [`crate::repair::Action::DisableStartupItem`].
    Entry,
    /// A scheduled task: [`crate::repair::Action::DisableScheduledTask`].
    Task { name: String },
}

/// Something that starts with the machine, as the threat tracer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Persist {
    pub id: String,
    pub name: String,
    pub scope: ItemScope,
    pub kind: PersistKind,
    /// The program it runs (a Startup shortcut's own target, read from the .lnk).
    pub target: Option<PathBuf>,
    /// The full command line, arguments included.
    pub command: String,
    /// The file whose presence starts it (Startup folder), if any.
    pub file: Option<PathBuf>,
}

/// Every entry that starts something (Windows: Run/RunOnce, Startup folders, scheduled tasks;
/// macOS and Linux: their user agents), with Startup shortcuts read without PowerShell.
pub fn persistence() -> Vec<Persist> {
    imp::gather()
        .into_iter()
        .filter_map(|r| {
            let (kind, file) = match &r.handle {
                Handle::RegValue { .. } => (PersistKind::Entry, None),
                Handle::File(f) => (PersistKind::Entry, Some(f.clone())),
                Handle::Task { name } => (PersistKind::Task { name: name.clone() }, None),
                Handle::ReadOnly => return None,
            };
            let mut target = r.target.clone();
            let mut command = r.command.clone();
            if let Some(f) = file.as_ref().filter(|f| f.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk"))) {
                if let Some(l) = std::fs::read(f).ok().and_then(|b| genra_av_core::heur::parse_lnk(&b)) {
                    command = format!("\"{}\" {}", l.target, l.arguments).trim_end().to_string();
                    target = (!l.target.is_empty()).then(|| PathBuf::from(expand_env(&l.target, |k| std::env::var(k).ok())));
                }
            }
            Some(Persist { id: r.id, name: r.name, scope: r.scope, kind, target, command, file })
        })
        .collect()
}

/// The entries that start one of `targets`: they run it, or name it on their command line. An
/// entry that *is* one of the targets (a script dropped straight into the Startup folder) is left
/// out: quarantining the target already removes it.
pub fn pointing_at<'a>(list: &'a [Persist], targets: &[PathBuf]) -> Vec<&'a Persist> {
    let key = |a: &Path| crate::journal::resolved(a).to_string_lossy().replace('/', "\\").to_lowercase();
    let same = |a: &Path, b: &Path| key(a) == key(b);
    list.iter()
        .filter(|p| !p.file.as_deref().is_some_and(|f| targets.iter().any(|t| same(f, t))))
        .filter(|p| {
            let command = expand_env(&p.command, |k| std::env::var(k).ok());
            targets.iter().any(|t| p.target.as_deref().is_some_and(|x| same(x, t)) || crate::traces::mentions(&command, t))
        })
        .collect()
}

// ---- command lines ----

/// Expands `%VAR%` with `env`; unknown variables stay as they are.
pub fn expand_env(s: &str, env: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) if j > 0 => match env(&after[..j]) {
                Some(v) => {
                    out.push_str(&v);
                    rest = &after[j + 1..];
                }
                None => {
                    out.push('%');
                    rest = after;
                }
            },
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// First argument of a command line: a quoted path, or the text up to the first `.exe` (paths
/// with spaces are often unquoted in Run keys), or the first word.
fn first_arg(cmd: &str) -> (String, &str) {
    let c = cmd.trim_start();
    if let Some(q) = c.strip_prefix('"') {
        return match q.find('"') {
            Some(i) => (q[..i].to_string(), &q[i + 1..]),
            None => (q.to_string(), ""),
        };
    }
    let lower = c.to_ascii_lowercase();
    for ext in [".exe", ".com", ".bat", ".cmd"] {
        if let Some(i) = lower.find(ext) {
            let end = i + ext.len();
            if c[end..].is_empty() || c[end..].starts_with(' ') {
                return (c[..end].to_string(), &c[end..]);
            }
        }
    }
    match c.find(char::is_whitespace) {
        Some(i) => (c[..i].to_string(), &c[i..]),
        None => (c.to_string(), ""),
    }
}

/// The file a Windows command line really runs: the program, or for script hosts (wscript,
/// cscript, mshta, rundll32, regsvr32, powershell -File, cmd /c) the script or DLL they load.
pub fn command_target(cmd: &str, env: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let cmd = expand_env(cmd, env);
    let (prog, mut rest) = first_arg(&cmd);
    if prog.is_empty() {
        return None;
    }
    let base = prog.replace('/', "\\").rsplit('\\').next().unwrap_or("").to_ascii_lowercase();
    let hosts = ["wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "powershell", "cmd"];
    if hosts.contains(&base.as_str()) {
        loop {
            let (arg, next) = first_arg(rest);
            if arg.is_empty() {
                break;
            }
            rest = next;
            let a = arg.trim_end_matches(',').to_string();
            if a.starts_with('/') || a.starts_with('-') {
                continue;
            }
            let a = a.split(',').next().unwrap_or("").to_string();
            if a.contains('\\') || a.contains('.') {
                return Some(PathBuf::from(a));
            }
        }
    }
    Some(PathBuf::from(prog))
}

// ---- schtasks ----

/// Fields of one CSV line (RFC 4180 quoting, as schtasks writes it).
pub fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub name: String,
    pub author: String,
    pub command: String,
    pub run_as: String,
}

/// Tasks from `schtasks /query /fo csv /v`. Columns are read by position (the header is
/// translated on non-English Windows): 1 TaskName, 7 Author, 8 Task To Run, 11 Scheduled Task
/// State, 14 Run As User. Repeated headers, Microsoft's own tasks, disabled tasks and duplicate
/// rows (one per trigger) are dropped.
pub fn parse_schtasks_csv(text: &str) -> Vec<Task> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let Some(header) = lines.next().map(csv_fields) else { return Vec::new() };
    let mut out: Vec<Task> = Vec::new();
    for l in lines {
        let f = csv_fields(l);
        if f.len() < 9 || f == header || f.get(1) == header.get(1) {
            continue;
        }
        let name = f[1].clone();
        if name.to_ascii_lowercase().starts_with("\\microsoft\\") || f[8].trim().is_empty() || f[8].eq_ignore_ascii_case("COM handler") {
            continue;
        }
        if f.get(11).is_some_and(|s| s.eq_ignore_ascii_case("disabled")) {
            continue;
        }
        if out.iter().any(|t| t.name == name) {
            continue;
        }
        out.push(Task { name, author: f[7].clone(), command: f[8].clone(), run_as: f.get(14).cloned().unwrap_or_default() });
    }
    out
}

// ---- PowerShell signatures ----

/// Reads the JSON our signature script prints: `{"lnk":{path:target}, "sig":{path:{"status":
/// "Valid", "publisher": "..."}}}`. PowerShell writes an empty hashtable as `{}` and may write a
/// missing value as `null`.
/// Lower-cased path → (signed, publisher).
pub type SignatureMap = HashMap<String, (Option<bool>, Option<String>)>;

pub fn parse_signature_json(text: &str) -> (HashMap<String, String>, SignatureMap) {
    let v: serde_json::Value = serde_json::from_str(text.trim().trim_start_matches('\u{feff}')).unwrap_or_default();
    let mut lnk = HashMap::new();
    if let Some(m) = v.get("lnk").and_then(|x| x.as_object()) {
        for (k, t) in m {
            if let Some(t) = t.as_str().filter(|t| !t.is_empty()) {
                lnk.insert(k.to_lowercase(), t.to_string());
            }
        }
    }
    let mut sig = HashMap::new();
    if let Some(m) = v.get("sig").and_then(|x| x.as_object()) {
        for (k, s) in m {
            let status = s.get("status").and_then(|x| x.as_str()).unwrap_or("");
            let signed = match status {
                "Valid" => Some(true),
                "NotSigned" | "HashMismatch" | "NotTrusted" | "Incompatible" => Some(false),
                _ => None,
            };
            let publisher = s.get("publisher").and_then(|x| x.as_str()).filter(|p| !p.is_empty()).map(String::from);
            sig.insert(k.to_lowercase(), (signed, publisher));
        }
    }
    (lnk, sig)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn signature_script(lnks: &[String], files: &[String]) -> String {
    let arr = |v: &[String]| format!("@({})", v.iter().map(|s| proc::ps_quote(s)).collect::<Vec<_>>().join(","));
    format!(
        "$lnk={};$in={};$lt=@{{}};$res=@{{}};\
         try{{$sh=New-Object -ComObject WScript.Shell;foreach($l in $lnk){{try{{$t=$sh.CreateShortcut($l).TargetPath;if($t){{$lt[$l]=$t}}}}catch{{}}}}}}catch{{}};\
         $all=@($in)+@($lt.Values);\
         foreach($p in $all){{try{{$s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop;$pub=$null;if($s.SignerCertificate){{$pub=$s.SignerCertificate.GetNameInfo('SimpleName',$false)}};$res[$p]=@{{status=[string]$s.Status;publisher=$pub}}}}catch{{}}}};\
         @{{lnk=$lt;sig=$res}}|ConvertTo-Json -Depth 4 -Compress",
        arr(lnks),
        arr(files)
    )
}

// ---- macOS ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchItem {
    pub label: String,
    pub program: Option<String>,
    pub arguments: Vec<String>,
    pub disabled: bool,
}

/// A launchd plist (XML or binary).
pub fn parse_launchd(bytes: &[u8]) -> Option<LaunchItem> {
    let v = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
    let d = v.as_dictionary()?;
    let label = d.get("Label").and_then(|x| x.as_string()).unwrap_or("").to_string();
    let program = d.get("Program").and_then(|x| x.as_string()).map(String::from);
    let arguments: Vec<String> = d.get("ProgramArguments").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_string().map(String::from)).collect()).unwrap_or_default();
    let disabled = d.get("Disabled").and_then(|x| x.as_boolean()).unwrap_or(false);
    Some(LaunchItem { label, program, arguments, disabled })
}

/// `codesign -dv --verbose=2` output (it writes to stderr): signed or not, and the first
/// Authority line as the publisher.
pub fn parse_codesign(stderr: &str, exit_ok: bool) -> (Option<bool>, Option<String>) {
    if stderr.contains("not signed at all") {
        return (Some(false), None);
    }
    if !exit_ok {
        return (None, None);
    }
    let publisher = stderr.lines().find_map(|l| l.strip_prefix("Authority=")).map(|s| s.trim().to_string());
    if stderr.contains("Signature=adhoc") {
        return (Some(false), None);
    }
    (Some(true), publisher)
}

// ---- Linux ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopEntry {
    pub name: String,
    pub exec: String,
    pub hidden: bool,
}

/// An XDG autostart `.desktop` file: `Name`, `Exec`, and whether it is switched off (`Hidden=true`
/// or `X-GNOME-Autostart-enabled=false`).
pub fn parse_desktop(text: &str) -> Option<DesktopEntry> {
    let mut in_entry = false;
    let (mut name, mut exec, mut hidden) = (String::new(), String::new(), false);
    for l in text.lines().map(str::trim) {
        if l.starts_with('[') {
            in_entry = l == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        match k.trim() {
            "Name" => name = v.trim().to_string(),
            "Exec" => exec = v.trim().to_string(),
            "Hidden" => hidden |= v.trim().eq_ignore_ascii_case("true"),
            "X-GNOME-Autostart-enabled" => hidden |= v.trim().eq_ignore_ascii_case("false"),
            _ => {}
        }
    }
    (!exec.is_empty()).then_some(DesktopEntry { name, exec, hidden })
}

#[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
fn which(prog: &str) -> Option<PathBuf> {
    if prog.contains('/') {
        return Some(PathBuf::from(prog));
    }
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(prog)).find(|c| c.is_file()))
}

// ---- gathering ----

fn tilde(p: &Path) -> String {
    match crate::home() {
        Some(h) if p.starts_with(&h) => format!("~{}{}", std::path::MAIN_SEPARATOR, p.strip_prefix(&h).map(|r| r.display().to_string()).unwrap_or_default()),
        _ => p.display().to_string(),
    }
}

fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir).map(|rd| rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_file())).map(|e| e.path()).collect()).unwrap_or_default();
    v.sort();
    v
}

fn xlstart_items() -> Vec<Raw> {
    let mut out = Vec::new();
    for dir in crate::repair::xlstart_dirs() {
        let user = crate::home().is_some_and(|h| dir.starts_with(h));
        for f in files_in(&dir) {
            let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if name.starts_with('.') && !name.eq_ignore_ascii_case(".personal") {
                continue;
            }
            out.push(Raw {
                id: format!("file:{}", f.display()),
                name: name.clone(),
                location: tilde(&dir),
                command: format!("Excel mở / opens {name}"),
                scope: if user { ItemScope::User } else { ItemScope::System },
                target: Some(f.clone()),
                handle: Handle::File(f),
                xlstart: true,
            });
        }
    }
    out
}

/// The item with this id now; scheduled tasks are only read when the id is one.
fn find(id: &str) -> Option<Raw> {
    #[cfg(windows)]
    let mut all = imp::gather_with(id.starts_with("task:"));
    #[cfg(not(windows))]
    let mut all = imp::gather();
    all.extend(xlstart_items());
    all.into_iter().find(|r| r.id == id)
}

/// The startup item `id` still exists (it may have gone since the plan was made).
pub(crate) fn exists(id: &str) -> bool {
    find(id).is_some()
}

fn gather() -> Vec<Raw> {
    let mut out = imp::gather();
    out.extend(xlstart_items());
    out
}

fn signatures(raws: &[Raw]) -> HashMap<String, Sig> {
    imp::signatures(raws)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::reg;

    fn env(k: &str) -> Option<String> {
        std::env::var(k).ok()
    }

    pub fn gather() -> Vec<Raw> {
        gather_with(true)
    }

    /// [`gather`], without the scheduled tasks (one slow `schtasks` call) when `tasks` is false.
    pub fn gather_with(tasks: bool) -> Vec<Raw> {
        let mut out = Vec::new();
        let run = "Software\\Microsoft\\Windows\\CurrentVersion";
        let keys = [
            (format!("HKCU\\{run}\\Run"), ItemScope::User),
            (format!("HKCU\\{run}\\RunOnce"), ItemScope::User),
            (format!("HKLM\\{run}\\Run"), ItemScope::System),
            (format!("HKLM\\{run}\\RunOnce"), ItemScope::System),
            ("HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(), ItemScope::System),
        ];
        for (key, scope) in keys {
            for (name, value) in reg::values(&key).unwrap_or_default() {
                let command = value.as_text();
                if command.trim().is_empty() {
                    continue;
                }
                out.push(Raw {
                    id: format!("run:{key}|{name}"),
                    name: if name.is_empty() { "(mặc định / default)".into() } else { name.clone() },
                    location: key.clone(),
                    target: command_target(&command, env),
                    command,
                    scope,
                    handle: Handle::RegValue { key: key.clone(), name },
                    xlstart: false,
                });
            }
        }
        let folders = [
            (env("APPDATA").map(|a| PathBuf::from(a).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")), ItemScope::User),
            (env("ProgramData").map(|a| PathBuf::from(a).join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp")), ItemScope::System),
        ];
        for (dir, scope) in folders {
            let Some(dir) = dir else { continue };
            for f in files_in(&dir) {
                let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if name.eq_ignore_ascii_case("desktop.ini") {
                    continue;
                }
                out.push(Raw {
                    id: format!("file:{}", f.display()),
                    name: f.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or(name),
                    location: tilde(&dir),
                    command: f.display().to_string(),
                    scope,
                    target: Some(f.clone()),
                    handle: Handle::File(f),
                    xlstart: false,
                });
            }
        }
        let schtasks = std::env::var_os("SystemRoot").map(|r| PathBuf::from(r).join("System32\\schtasks.exe")).filter(|p| tasks && p.is_file());
        if let Some(exe) = schtasks {
            if let Ok(o) = proc::run(&exe.to_string_lossy(), &["/query", "/fo", "csv", "/v"], Duration::from_secs(30)) {
                for t in parse_schtasks_csv(&o.stdout) {
                    out.push(Raw {
                        id: format!("task:{}", t.name),
                        name: t.name.trim_start_matches('\\').to_string(),
                        location: "Task Scheduler".into(),
                        target: command_target(&t.command, env),
                        command: t.command,
                        scope: ItemScope::System,
                        handle: Handle::Task { name: t.name.clone() },
                        xlstart: false,
                    });
                }
            }
        }
        out
    }

    pub fn signatures(raws: &[Raw]) -> HashMap<String, Sig> {
        let mut lnks: Vec<String> = Vec::new();
        let mut files: Vec<String> = Vec::new();
        for r in raws.iter().filter(|r| !r.xlstart) {
            let Some(t) = &r.target else { continue };
            let s = t.display().to_string();
            if s.to_ascii_lowercase().ends_with(".lnk") {
                lnks.push(s);
            } else if t.is_file() {
                files.push(s);
            }
        }
        lnks.sort();
        lnks.dedup();
        files.sort();
        files.dedup();
        let (mut lt, mut sg) = (HashMap::new(), HashMap::new());
        // Batches keep the encoded command well under Windows' 32 767-character limit.
        let mut i = 0;
        while i < lnks.len().max(files.len()) {
            let l = &lnks[i.min(lnks.len())..(i + 30).min(lnks.len())];
            let f = &files[i.min(files.len())..(i + 30).min(files.len())];
            i += 30;
            if let Ok(o) = proc::powershell(&signature_script(l, f), Duration::from_secs(45)) {
                let (a, b) = parse_signature_json(&o.stdout);
                lt.extend(a);
                sg.extend(b);
            }
        }
        let mut out = HashMap::new();
        for r in raws {
            let Some(t) = &r.target else { continue };
            let key = t.display().to_string().to_lowercase();
            let resolved = lt.get(&key).map(PathBuf::from);
            let sig_key = resolved.as_ref().map(|p| p.display().to_string().to_lowercase()).unwrap_or(key);
            let (signed, publisher) = sg.get(&sig_key).cloned().unwrap_or((None, None));
            out.insert(r.id.clone(), Sig { signed, publisher, resolved });
        }
        out
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    pub fn gather() -> Vec<Raw> {
        let mut out = Vec::new();
        let mut dirs = Vec::new();
        if let Some(h) = crate::home() {
            dirs.push((h.join("Library/LaunchAgents"), ItemScope::User, false));
        }
        dirs.push((PathBuf::from("/Library/LaunchAgents"), ItemScope::System, false));
        dirs.push((PathBuf::from("/Library/LaunchDaemons"), ItemScope::System, true));
        for (dir, scope, read_only) in dirs {
            for f in files_in(&dir) {
                if f.extension().and_then(|e| e.to_str()) != Some("plist") {
                    continue;
                }
                let Ok(bytes) = std::fs::read(&f) else { continue };
                let Some(item) = parse_launchd(&bytes) else { continue };
                if item.disabled {
                    continue;
                }
                let prog = item.program.clone().or_else(|| item.arguments.first().cloned());
                if prog.is_none() {
                    continue; // An empty plist runs nothing.
                }
                let command = if item.arguments.is_empty() { prog.clone().unwrap_or_default() } else { item.arguments.join(" ") };
                let name = if item.label.is_empty() { f.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default() } else { item.label.clone() };
                out.push(Raw {
                    id: format!("file:{}", f.display()),
                    name,
                    location: tilde(&dir),
                    command,
                    scope,
                    target: prog.map(PathBuf::from),
                    handle: if read_only { Handle::ReadOnly } else { Handle::File(f) },
                    xlstart: false,
                });
            }
        }
        out
    }

    pub fn signatures(raws: &[Raw]) -> HashMap<String, Sig> {
        let mut cache: HashMap<PathBuf, (Option<bool>, Option<String>)> = HashMap::new();
        let mut out = HashMap::new();
        for r in raws.iter().filter(|r| !r.xlstart).take(200) {
            let Some(t) = r.target.clone().filter(|t| t.exists()) else { continue };
            let v = cache
                .entry(t.clone())
                .or_insert_with(|| match proc::run("/usr/bin/codesign", &["-dv", "--verbose=2", &t.to_string_lossy()], Duration::from_secs(10)) {
                    Ok(o) => parse_codesign(&o.stderr, o.ok()),
                    Err(_) => (None, None),
                })
                .clone();
            out.insert(r.id.clone(), Sig { signed: v.0, publisher: v.1, resolved: None });
        }
        out
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use super::*;

    pub fn gather() -> Vec<Raw> {
        let mut out = Vec::new();
        let user_dir = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| crate::home().map(|h| h.join(".config"))).map(|c| c.join("autostart"));
        let mut user_names = std::collections::HashSet::new();
        let dirs = [(user_dir, ItemScope::User), (Some(PathBuf::from("/etc/xdg/autostart")), ItemScope::System)];
        for (dir, scope) in dirs {
            let Some(dir) = dir else { continue };
            for f in files_in(&dir) {
                if f.extension().and_then(|e| e.to_str()) != Some("desktop") {
                    continue;
                }
                let fname = f.file_name().map(|n| n.to_os_string()).unwrap_or_default();
                // A user file with the same name overrides the system one.
                if scope == ItemScope::System && user_names.contains(&fname) {
                    continue;
                }
                if scope == ItemScope::User {
                    user_names.insert(fname);
                }
                let Some(d) = std::fs::read_to_string(&f).ok().and_then(|t| parse_desktop(&t)) else { continue };
                if d.hidden {
                    continue;
                }
                let prog = d.exec.split_whitespace().next().unwrap_or("").to_string();
                out.push(Raw {
                    id: format!("file:{}", f.display()),
                    name: if d.name.is_empty() { f.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default() } else { d.name },
                    location: tilde(&dir),
                    command: d.exec.clone(),
                    scope,
                    target: which(&prog),
                    handle: Handle::File(f),
                    xlstart: false,
                });
            }
        }
        out
    }

    pub fn signatures(_: &[Raw]) -> HashMap<String, Sig> {
        HashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(k: &str) -> Option<String> {
        match k {
            "APPDATA" => Some("C:\\Users\\a\\AppData\\Roaming".into()),
            "ProgramFiles" => Some("C:\\Program Files".into()),
            _ => None,
        }
    }

    #[test]
    fn command_lines() {
        let t = |c: &str| command_target(c, env).map(|p| p.display().to_string());
        assert_eq!(t("\"C:\\Program Files\\App\\app.exe\" --tray").as_deref(), Some("C:\\Program Files\\App\\app.exe"));
        assert_eq!(t("C:\\Program Files\\Some App\\run.exe /background").as_deref(), Some("C:\\Program Files\\Some App\\run.exe"));
        assert_eq!(t("%APPDATA%\\x\\up.exe").as_deref(), Some("C:\\Users\\a\\AppData\\Roaming\\x\\up.exe"));
        assert_eq!(t("wscript.exe //B \"%APPDATA%\\Microsoft\\w.vbs\"").as_deref(), Some("C:\\Users\\a\\AppData\\Roaming\\Microsoft\\w.vbs"));
        assert_eq!(t("rundll32.exe C:\\Users\\a\\x.dll,Start").as_deref(), Some("C:\\Users\\a\\x.dll"));
        assert_eq!(t("powershell.exe -w hidden -File C:\\t\\a.ps1").as_deref(), Some("C:\\t\\a.ps1"));
        assert_eq!(t("%UNKNOWN%\\a.exe").as_deref(), Some("%UNKNOWN%\\a.exe"));
        assert_eq!(t("   "), None);
    }

    #[test]
    fn risky_places() {
        assert!(risky_location(Path::new("C:\\Users\\a\\AppData\\Roaming\\x\\up.exe")));
        assert!(risky_location(Path::new("C:\\Users\\a\\Downloads\\setup.exe")));
        assert!(risky_location(Path::new("/Users/a/Library/Application Support/x/agent")));
        assert!(!risky_location(Path::new("C:\\Program Files\\App\\app.exe")));
        assert!(!risky_location(Path::new("/Applications/Zalo.app/Contents/MacOS/Zalo")));
    }

    #[test]
    fn schtasks_csv() {
        let text = concat!(
            "\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Logon Mode\",\"Last Run Time\",\"Last Result\",\"Author\",\"Task To Run\",\"Start In\",\"Comment\",\"Scheduled Task State\",\"Idle Time\",\"Power Management\",\"Run As User\"\r\n",
            "\"PC\",\"\\Updater\",\"N/A\",\"Ready\",\"Interactive only\",\"N/A\",\"1\",\"PC\\a\",\"C:\\Users\\a\\AppData\\Local\\u.exe /x\",\"N/A\",\"N/A\",\"Enabled\",\"\",\"\",\"a\"\r\n",
            "\"PC\",\"\\Updater\",\"N/A\",\"Ready\",\"Interactive only\",\"N/A\",\"1\",\"PC\\a\",\"C:\\Users\\a\\AppData\\Local\\u.exe /x\",\"N/A\",\"N/A\",\"Enabled\",\"\",\"\",\"a\"\r\n",
            "\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Logon Mode\",\"Last Run Time\",\"Last Result\",\"Author\",\"Task To Run\",\"Start In\",\"Comment\",\"Scheduled Task State\",\"Idle Time\",\"Power Management\",\"Run As User\"\r\n",
            "\"PC\",\"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\",\"N/A\",\"Ready\",\"\",\"\",\"0\",\"Microsoft\",\"%windir%\\system32\\defrag.exe -c\",\"\",\"\",\"Enabled\",\"\",\"\",\"SYSTEM\"\r\n",
            "\"PC\",\"\\Off\",\"N/A\",\"Disabled\",\"\",\"\",\"0\",\"x\",\"C:\\off.exe\",\"\",\"\",\"Disabled\",\"\",\"\",\"a\"\r\n",
            "\"PC\",\"\\Has \"\"quotes\"\"\",\"N/A\",\"Ready\",\"\",\"\",\"0\",\"x\",\"\"\"C:\\Program Files\\q.exe\"\" -a\",\"\",\"\",\"Enabled\",\"\",\"\",\"a\"\r\n",
        );
        let tasks = parse_schtasks_csv(text);
        assert_eq!(tasks.len(), 2, "{tasks:?}");
        assert_eq!(tasks[0].name, "\\Updater");
        assert_eq!(tasks[0].command, "C:\\Users\\a\\AppData\\Local\\u.exe /x");
        assert_eq!(tasks[1].name, "\\Has \"quotes\"");
        assert_eq!(command_target(&tasks[1].command, env).unwrap(), PathBuf::from("C:\\Program Files\\q.exe"));
        assert!(parse_schtasks_csv("").is_empty());
    }

    #[test]
    fn signature_json() {
        let text = "\u{feff}{\"lnk\":{\"C:\\\\Users\\\\a\\\\Startup\\\\Zalo.lnk\":\"C:\\\\Users\\\\a\\\\AppData\\\\Local\\\\Programs\\\\Zalo\\\\Zalo.exe\"},\"sig\":{\"C:\\\\Users\\\\a\\\\AppData\\\\Local\\\\Programs\\\\Zalo\\\\Zalo.exe\":{\"status\":\"Valid\",\"publisher\":\"VNG ONLINE CO.,LTD\"},\"C:\\\\t\\\\x.exe\":{\"status\":\"NotSigned\",\"publisher\":null},\"C:\\\\t\\\\y.exe\":{\"status\":\"UnknownError\",\"publisher\":null}}}";
        let (lnk, sig) = parse_signature_json(text);
        assert_eq!(lnk["c:\\users\\a\\startup\\zalo.lnk"], "C:\\Users\\a\\AppData\\Local\\Programs\\Zalo\\Zalo.exe");
        assert_eq!(sig["c:\\users\\a\\appdata\\local\\programs\\zalo\\zalo.exe"], (Some(true), Some("VNG ONLINE CO.,LTD".into())));
        assert_eq!(sig["c:\\t\\x.exe"], (Some(false), None));
        assert_eq!(sig["c:\\t\\y.exe"], (None, None));
        let (a, b) = parse_signature_json("{\"lnk\":{},\"sig\":{}}");
        assert!(a.is_empty() && b.is_empty());
        assert!(parse_signature_json("garbage").1.is_empty());
        let s = signature_script(&["C:\\it's.lnk".into()], &[]);
        assert!(s.contains("'C:\\it''s.lnk'") && s.contains("$in=@()"));
    }

    #[test]
    fn launchd_plists() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.example.updater</string>
<key>ProgramArguments</key><array><string>/Users/a/Library/Application Support/x/agent</string><string>--run</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>"#;
        let item = parse_launchd(xml).unwrap();
        assert_eq!(item.label, "com.example.updater");
        assert_eq!(item.arguments, ["/Users/a/Library/Application Support/x/agent", "--run"]);
        assert!(!item.disabled && item.program.is_none());
        let mut bin = Vec::new();
        plist::Value::from_reader(std::io::Cursor::new(&xml[..])).unwrap().to_writer_binary(&mut bin).unwrap();
        assert_eq!(parse_launchd(&bin).unwrap(), item, "binary plists too");
        assert!(parse_launchd(b"not a plist").is_none());
    }

    #[test]
    fn codesign_output() {
        let signed = "Executable=/Applications/Zalo.app/Contents/MacOS/Zalo\nIdentifier=com.vng.zalo\nAuthority=Developer ID Application: VNG ONLINE CO.,LTD (ABCDE12345)\nAuthority=Developer ID Certification Authority\nTeamIdentifier=ABCDE12345\n";
        assert_eq!(parse_codesign(signed, true), (Some(true), Some("Developer ID Application: VNG ONLINE CO.,LTD (ABCDE12345)".into())));
        assert_eq!(parse_codesign("/tmp/x: code object is not signed at all\n", false), (Some(false), None));
        assert_eq!(parse_codesign("Signature=adhoc\n", true), (Some(false), None));
        assert_eq!(parse_codesign("error: no such file", false), (None, None));
    }

    #[test]
    fn desktop_files() {
        let d = parse_desktop("[Desktop Entry]\nName=Updater\nExec=/home/a/.local/share/u/run --bg\n[Other]\nExec=ignored\n").unwrap();
        assert_eq!(d, DesktopEntry { name: "Updater".into(), exec: "/home/a/.local/share/u/run --bg".into(), hidden: false });
        assert!(parse_desktop("[Desktop Entry]\nExec=x\nX-GNOME-Autostart-enabled=false\n").unwrap().hidden);
        assert!(parse_desktop("[Desktop Entry]\nName=x\n").is_none());
    }

    #[test]
    fn secrets_are_masked() {
        assert_eq!(mask_secrets("/opt/homebrew/bin/cloudflared tunnel run --token eyJhIjoiMjUzMThjZmU4MmI3ZmNhNjkwMDE1YmNi"), "/opt/homebrew/bin/cloudflared tunnel run --token …");
        assert_eq!(mask_secrets("app --password=hunter2 -v"), "app --password=… -v");
        assert_eq!(mask_secrets("app ZmFrZWtleWZha2VrZXlmYWtla2V5ZmFrZWtleWZha2Vr x"), "app … x");
        let path = "\"C:\\Program Files\\Very Long Vendor Name\\Application\\app.exe\" --tray";
        assert_eq!(mask_secrets(path), path, "paths are not keys");
    }

    #[test]
    fn env_expansion() {
        assert_eq!(expand_env("%APPDATA%\\a %X% 50%", env), "C:\\Users\\a\\AppData\\Roaming\\a %X% 50%");
        assert_eq!(expand_env("%%", env), "%%");
    }

    #[test]
    fn judging() {
        let root = std::env::temp_dir().join(format!("genra-machine-st-{}", std::process::id()));
        let dl = root.join("Downloads");
        std::fs::create_dir_all(&dl).unwrap();
        let exe = dl.join("u.exe");
        std::fs::write(&exe, b"MZ not much").unwrap();
        let raw = Raw { id: "x".into(), name: "u".into(), location: "l".into(), command: "c".into(), scope: ItemScope::User, target: Some(exe.clone()), handle: Handle::ReadOnly, xlstart: false };
        let unsigned = Sig { signed: Some(false), publisher: None, resolved: None };
        assert_eq!(judge(&raw, Some(&unsigned), None, None).verdict, Verdict::Warn);
        let signed = Sig { signed: Some(true), publisher: Some("P".into()), resolved: None };
        let ok = judge(&raw, Some(&signed), None, None);
        assert_eq!(ok.verdict, Verdict::Ok);
        assert!(ok.reason_vi.contains("(P)"));
        let sha = crate::sha256_hex(b"MZ not much");
        let pack = Pack::parse(format!(r#"{{"format":1,"version":1,"published":"x","rules":[{{"id":"r","family":"Fam","severity":"malware","message_vi":"m","when":{{"sha256_any":["{sha}"]}}}}]}}"#).as_bytes()).unwrap();
        let bad = judge(&raw, Some(&signed), Some(&pack), None);
        assert_eq!(bad.verdict, Verdict::Bad, "a match beats a signature");
        assert!(bad.reason_en.contains("Fam"));
        let missing = Raw { target: Some(root.join("gone.exe")), ..raw };
        assert_eq!(judge(&missing, None, None, None).verdict, Verdict::Unknown);
        let _ = std::fs::remove_dir_all(&root);
    }
}
