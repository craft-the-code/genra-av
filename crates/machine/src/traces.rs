//! What a threat leaves on the machine besides its own file (ADR 0004, 4b): the program still
//! running, entries that start it with Windows, and settings malware locks so the user cannot
//! look (Task Manager, Registry Editor, Folder Options).
//!
//! Everything here is traced to the threat's own path: a process is the threat's only when its
//! program *is* the threat or its command line names the threat's path; a startup entry only when
//! it runs or names that path. The locked settings are the one exception (malware sets them
//! machine-wide, not per file), so they are only offered for a malware-level threat and never on
//! a machine an organisation manages (its IT sets these on purpose).

#[cfg(windows)]
use crate::proc;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::Duration;

/// A running process, as listed once when the plan is made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Running {
    pub pid: u32,
    /// When it started (as Windows reports it), so a reused process id is never stopped.
    pub started: String,
    pub exe: Option<PathBuf>,
    pub command: String,
}

/// Programs never stopped, whatever their command line says: the shell, Office (it holds the
/// user's documents; Excel is asked to close instead), and Windows' own core processes.
const NEVER_STOP: &[&str] = &[
    "explorer.exe", "excel.exe", "winword.exe", "powerpnt.exe", "outlook.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe",
    "services.exe", "smss.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe", "taskhostw.exe", "msmpeng.exe", "genra-av-app.exe",
    "genra-av.exe", "genra av.exe",
];

fn norm(s: &str) -> String {
    s.replace('/', "\\").to_lowercase()
}

/// `command` names `path` as a whole argument: the path (any case, either slash) with nothing
/// path-like right before or after it, so `C:\a\x.js` does not match `C:\a\x.json` or `D:\b\C:\a\x.js`.
pub fn mentions(command: &str, path: &Path) -> bool {
    let p = norm(&path.to_string_lossy());
    if p.len() < 4 {
        return false;
    }
    let c = norm(command);
    let edge = |ch: Option<char>| ch.is_none_or(|ch| matches!(ch, '"' | '\'' | ' ' | '\t' | '=' | ',' | ';' | '(' | ')'));
    let mut from = 0;
    while let Some(i) = c[from..].find(&p) {
        let at = from + i;
        let before = c[..at].chars().next_back();
        let after = c[at + p.len()..].chars().next();
        if edge(before) && edge(after) {
            return true;
        }
        from = at + 1;
        while !c.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}

/// The last part of a path, splitting on either slash (a Windows path read on any system).
pub fn base_name(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.rsplit(['\\', '/']).next().unwrap_or(&s).to_string()
}

fn same_path(a: &Path, b: &Path) -> bool {
    norm(&a.to_string_lossy()) == norm(&b.to_string_lossy())
}

/// The processes that are the threat running: the program is one of `targets`, or its command
/// line names one (a script host running the worm's script). Never Genra itself, the shell,
/// Office or Windows' core.
pub fn processes_of<'a>(list: &'a [Running], targets: &[PathBuf]) -> Vec<(&'a Running, PathBuf)> {
    let me = std::process::id();
    let mut out = Vec::new();
    for r in list {
        if r.pid == me || r.pid <= 4 {
            continue;
        }
        let exe_name = r.exe.as_deref().map(|e| base_name(e).to_lowercase());
        if exe_name.as_deref().is_some_and(|n| NEVER_STOP.contains(&n)) {
            continue;
        }
        let hit = targets.iter().find(|t| r.exe.as_deref().is_some_and(|e| same_path(e, t)) || mentions(&r.command, t));
        if let Some(t) = hit {
            out.push((r, t.clone()));
        }
    }
    out
}

/// Processes running now (Windows: one hidden PowerShell call; elsewhere empty: the threats this
/// step is for are Windows programs and scripts).
pub fn running() -> Vec<Running> {
    #[cfg(windows)]
    {
        let script = "Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{ pid = [uint32]$_.ProcessId; started = $(if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { '' }); exe = $_.ExecutablePath; command = [string]$_.CommandLine } } | ConvertTo-Json -Compress";
        match proc::powershell(script, Duration::from_secs(30)) {
            Ok(o) => parse_running(&o.stdout),
            Err(_) => Vec::new(),
        }
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Reads the JSON [`running`]'s script prints (an object when there is one process, an array
/// otherwise; `exe` may be null for processes of other users).
pub fn parse_running(text: &str) -> Vec<Running> {
    #[derive(Deserialize)]
    struct P {
        pid: u32,
        #[serde(default)]
        started: Option<String>,
        #[serde(default)]
        exe: Option<String>,
        #[serde(default)]
        command: Option<String>,
    }
    let t = text.trim().trim_start_matches('\u{feff}');
    let list: Vec<P> = if t.starts_with('[') { serde_json::from_str(t).unwrap_or_default() } else { serde_json::from_str::<P>(t).map(|p| vec![p]).unwrap_or_default() };
    list.into_iter()
        .map(|p| Running {
            pid: p.pid,
            started: p.started.unwrap_or_default(),
            exe: p.exe.filter(|e| !e.is_empty()).map(PathBuf::from),
            command: p.command.unwrap_or_default(),
        })
        .collect()
}

/// How stopping a process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    Stopped,
    /// Already gone, or the id now belongs to another program: nothing done.
    Gone,
    /// Windows refused (the threat runs with admin rights). With its startup entries switched off
    /// it does not come back after a restart.
    Refused,
}

/// Stops process `pid` if it is still the one listed (same start time, still the threat).
pub fn stop(pid: u32, started: &str, path: &Path) -> Result<Stopped> {
    #[cfg(windows)]
    {
        let p = proc::ps_quote(&path.to_string_lossy());
        let s = proc::ps_quote(started);
        let script = format!(
            "$p = Get-CimInstance Win32_Process -Filter 'ProcessId={pid}'; \
             if (-not $p) {{ 'gone'; exit }}; \
             $t = $(if ($p.CreationDate) {{ $p.CreationDate.ToUniversalTime().ToString('o') }} else {{ '' }}); \
             if ($t -ne {s}) {{ 'gone'; exit }}; \
             $e = [string]$p.ExecutablePath; $c = ([string]$p.CommandLine).ToLower(); \
             if (-not ($e -ieq {p} -or $c.Contains({p}.ToLower()))) {{ 'gone'; exit }}; \
             try {{ Stop-Process -Id {pid} -Force -ErrorAction Stop }} catch {{ 'refused'; exit }}; \
             $n = 0; while ((Get-Process -Id {pid} -ErrorAction SilentlyContinue) -and $n -lt 30) {{ Start-Sleep -Milliseconds 100; $n++ }}; \
             if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ 'refused' }} else {{ 'stopped' }}"
        );
        let o = proc::powershell(&script, Duration::from_secs(20))?;
        match o.stdout.trim() {
            "stopped" => Ok(Stopped::Stopped),
            "gone" => Ok(Stopped::Gone),
            "refused" => Ok(Stopped::Refused),
            other => bail!("stopping process {pid}: unexpected answer {other:?} ({})", o.stderr.trim()),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, started, path);
        bail!("stopping a process is done on Windows only")
    }
}

// ---- scheduled tasks ----

/// `\\Folder\\Name` → (`\\Folder\\`, `Name`), the form the ScheduledTasks cmdlets take.
pub fn split_task(full: &str) -> (String, String) {
    let full = if full.starts_with('\\') { full.to_string() } else { format!("\\{full}") };
    let i = full.rfind('\\').unwrap_or(0);
    (full[..=i].to_string(), full[i + 1..].to_string())
}

/// Whether a task is enabled now: `Some(true)` enabled, `Some(false)` disabled, `None` gone.
pub fn task_enabled(full: &str) -> Result<Option<bool>> {
    #[cfg(windows)]
    {
        let (path, name) = split_task(full);
        let script = format!(
            "$t = Get-ScheduledTask -TaskPath {} -TaskName {} -ErrorAction SilentlyContinue; if (-not $t) {{ 'gone' }} elseif ($t.State.ToString() -eq 'Disabled') {{ 'off' }} else {{ 'on' }}",
            proc::ps_quote(&path),
            proc::ps_quote(&name)
        );
        let o = proc::powershell(&script, Duration::from_secs(20))?;
        match o.stdout.trim() {
            "on" => Ok(Some(true)),
            "off" => Ok(Some(false)),
            "gone" => Ok(None),
            other => bail!("reading task {full}: unexpected answer {other:?} ({})", o.stderr.trim()),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = full;
        bail!("scheduled tasks exist on Windows only")
    }
}

/// Switches a task on or off (a task this user made; others need admin rights and fail).
pub fn set_task_enabled(full: &str, on: bool) -> Result<()> {
    #[cfg(windows)]
    {
        let (path, name) = split_task(full);
        let verb = if on { "Enable-ScheduledTask" } else { "Disable-ScheduledTask" };
        let script = format!("try {{ {verb} -TaskPath {} -TaskName {} -ErrorAction Stop | Out-Null; 'ok' }} catch {{ 'error: ' + $_.Exception.Message }}", proc::ps_quote(&path), proc::ps_quote(&name));
        let o = proc::powershell(&script, Duration::from_secs(20))?;
        if o.stdout.trim() == "ok" {
            Ok(())
        } else {
            bail!("{verb} {full}: {}", o.stdout.trim())
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (full, on);
        bail!("scheduled tasks exist on Windows only")
    }
}

// ---- locked settings ----

/// Settings malware switches on so the user cannot look: (key, value name, what the user sees).
pub const LOCKS: &[(&str, &str, &str, &str)] = &[
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableTaskMgr", "Trình quản lý tác vụ (Task Manager)", "Task Manager"),
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableRegistryTools", "Trình sửa Registry", "Registry Editor"),
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoFolderOptions", "Tuỳ chọn thư mục (hiện tệp ẩn)", "Folder Options (show hidden files)"),
];

/// Where a lock goes when it is lifted (moved, not deleted, so undo puts it back).
pub fn lock_backup(key: &str) -> String {
    format!("HKCU\\Software\\Genra AV\\LiftedLocks\\{}", key.rsplit('\\').next().unwrap_or("System"))
}

/// The machine is managed by an organisation (joined to a domain): its IT may set these on purpose.
pub fn managed(env: impl Fn(&str) -> Option<String>) -> bool {
    env("USERDNSDOMAIN").is_some_and(|d| !d.trim().is_empty())
}

/// The locks switched on for this user now (empty on a managed machine and off Windows).
pub fn locks_on() -> Vec<(String, String)> {
    if !cfg!(windows) || managed(|k| std::env::var(k).ok()) {
        return Vec::new();
    }
    LOCKS
        .iter()
        .filter(|(key, name, ..)| matches!(crate::reg::get(key, name), Ok(Some(crate::reg::RegValue::Dword(n))) if n != 0))
        .map(|(k, n, ..)| (k.to_string(), n.to_string()))
        .collect()
}

/// What the user sees for a lock: (vi, en).
pub fn lock_label(key: &str, name: &str) -> Option<(&'static str, &'static str)> {
    LOCKS.iter().find(|(k, n, ..)| k.eq_ignore_ascii_case(key) && n.eq_ignore_ascii_case(name)).map(|(_, _, vi, en)| (*vi, *en))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mentions_whole_paths_only() {
        let p = Path::new("C:\\Users\\a\\AppData\\Roaming\\x.js");
        assert!(mentions("\"C:\\Windows\\System32\\wscript.exe\" \"C:\\Users\\a\\AppData\\Roaming\\x.js\"", p));
        assert!(mentions("wscript.exe c:/users/A/appdata/roaming/X.JS //B", p));
        assert!(!mentions("wscript.exe C:\\Users\\a\\AppData\\Roaming\\x.json", p));
        assert!(!mentions("wscript.exe D:\\b\\C:\\Users\\a\\AppData\\Roaming\\x.js", p));
        assert!(!mentions("anything", Path::new("C:")));
    }

    fn r(pid: u32, exe: &str, command: &str) -> Running {
        Running { pid, started: "t".into(), exe: (!exe.is_empty()).then(|| PathBuf::from(exe)), command: command.into() }
    }

    #[test]
    fn only_the_threat_is_stopped() {
        let threat = PathBuf::from("C:\\Users\\a\\AppData\\Roaming\\svc\\update.exe");
        let script = PathBuf::from("E:\\_\\x.js");
        let list = vec![
            r(100, "C:\\Users\\a\\AppData\\Roaming\\svc\\update.exe", "update.exe"),
            r(101, "C:\\Windows\\System32\\wscript.exe", "wscript.exe /e:vbs \"E:\\_\\x.js\""),
            r(102, "C:\\Windows\\explorer.exe", "explorer.exe \"E:\\_\\x.js\""),
            r(103, "C:\\Program Files\\Microsoft Office\\EXCEL.EXE", "EXCEL.EXE C:\\Users\\a\\AppData\\Roaming\\svc\\update.exe"),
            r(104, "C:\\Windows\\notepad.exe", "notepad.exe C:\\Users\\a\\notes.txt"),
            r(105, "", "update.exe"),
            r(std::process::id(), "C:\\x\\genra.exe", "E:\\_\\x.js"),
        ];
        let hits = processes_of(&list, &[threat.clone(), script.clone()]);
        let pids: Vec<u32> = hits.iter().map(|(p, _)| p.pid).collect();
        assert_eq!(pids, [100, 101]);
        assert_eq!(hits[1].1, script);
    }

    #[test]
    fn process_json() {
        let one = r#"{"pid":7,"started":"2026-11-27T01:02:03.0000000Z","exe":"C:\\a.exe","command":"a.exe"}"#;
        assert_eq!(parse_running(one), vec![Running { pid: 7, started: "2026-11-27T01:02:03.0000000Z".into(), exe: Some("C:\\a.exe".into()), command: "a.exe".into() }]);
        let many = "\u{feff}[{\"pid\":1,\"started\":null,\"exe\":null,\"command\":null},{\"pid\":2,\"started\":\"\",\"exe\":\"\",\"command\":\"x\"}]";
        let l = parse_running(many);
        assert_eq!(l.len(), 2);
        assert!(l[0].exe.is_none() && l[1].exe.is_none() && l[1].command == "x");
        assert!(parse_running("garbage").is_empty());
    }

    #[test]
    fn task_names() {
        assert_eq!(split_task("\\Updater\\Daily"), ("\\Updater\\".to_string(), "Daily".to_string()));
        assert_eq!(split_task("Daily"), ("\\".to_string(), "Daily".to_string()));
    }

    #[test]
    fn locks() {
        assert!(managed(|k| (k == "USERDNSDOMAIN").then(|| "CORP.EXAMPLE".to_string())));
        assert!(!managed(|_| None));
        assert_eq!(lock_backup(LOCKS[0].0), "HKCU\\Software\\Genra AV\\LiftedLocks\\System");
        assert_eq!(lock_label(&LOCKS[2].0.to_lowercase(), "nofolderoptions").map(|l| l.1), Some("Folder Options (show hidden files)"));
        assert!(lock_label("HKCU\\Software\\X", "DisableTaskMgr").is_none());
    }

    /// Windows only: a real process is found by its command line and stopped; a reused id or a
    /// changed command line is left alone.
    #[cfg(windows)]
    #[test]
    fn stops_a_real_process_found_by_its_command_line() {
        let dir = std::env::temp_dir().join(format!("genra-traces-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("worm.js");
        std::fs::write(&marker, b"x").unwrap();
        // A harmless long-running process that names the "threat" on its command line.
        let mut child = std::process::Command::new("cmd.exe").args(["/c", "ping", "-n", "60", "127.0.0.1", ">nul", "&", "rem"]).arg(&marker).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(800));
        let list = running();
        let hits = processes_of(&list, std::slice::from_ref(&marker));
        let me = hits.iter().find(|(p, _)| p.pid == child.id()).map(|(p, _)| (*p).clone()).expect("the child is found by its command line");
        assert_eq!(stop(me.pid, "1999-01-01T00:00:00.0000000Z", &marker).unwrap(), Stopped::Gone, "another start time: not ours");
        assert_eq!(stop(me.pid, &me.started, &dir.join("other.js")).unwrap(), Stopped::Gone, "does not name this threat");
        assert_eq!(stop(me.pid, &me.started, &marker).unwrap(), Stopped::Stopped);
        assert!(child.try_wait().unwrap().is_some() || child.wait().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Windows only: a task this user made is switched off through the journal and undo
    /// switches it on again.
    #[cfg(windows)]
    #[test]
    fn switches_a_real_task_off_and_undo_on() {
        let name = format!("\\GenraTest\\t{}", std::process::id());
        let ok = std::process::Command::new("schtasks.exe")
            .args(["/create", "/tn", &name, "/tr", "cmd.exe /c rem", "/sc", "once", "/st", "23:59", "/f"])
            .output()
            .unwrap();
        assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
        assert_eq!(task_enabled(&name).unwrap(), Some(true));
        let data = std::env::temp_dir().join(format!("genra-traces-j-{}", std::process::id()));
        let mut j = crate::journal::Journal::open(&data).unwrap();
        let g = crate::journal::Journal::new_group_id().unwrap();
        j.disable_task(&g, &name, "tắt", "off").unwrap();
        assert_eq!(task_enabled(&name).unwrap(), Some(false));
        j.undo_group(&g).unwrap();
        assert_eq!(task_enabled(&name).unwrap(), Some(true));
        let _ = std::process::Command::new("schtasks.exe").args(["/delete", "/tn", &name, "/f"]).output();
        assert_eq!(task_enabled(&name).unwrap(), None);
        let _ = std::fs::remove_dir_all(&data);
    }
}
