//! Helper processes (PowerShell, schtasks, osascript, spctl, codesign): always with a timeout,
//! never with a window, stdin closed, output read on threads so a full pipe cannot hang us.
//! A process that runs past its timeout is ended; it is our own helper, never the user's app.

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg_attr(windows, allow(dead_code))]
pub struct Output {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    #[cfg_attr(windows, allow(dead_code))]
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

pub fn run(program: &str, args: &[&str], timeout: Duration) -> Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().with_context(|| format!("starting {program}"))?;
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    let t_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let t_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let started = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} did not finish within {} s", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
    Ok(Output { status: status.code(), stdout, stderr })
}

/// Runs a PowerShell script hidden, with no profile, passed as `-EncodedCommand` (so quoting in
/// paths cannot break out of it). Output is forced to UTF-8.
#[cfg(windows)]
pub fn powershell(script: &str, timeout: Duration) -> Result<Output> {
    let exe = std::env::var_os("SystemRoot")
        .map(|r| std::path::PathBuf::from(r).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
        .filter(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "powershell.exe".into());
    let full = format!("$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;{script}");
    let encoded = encoded_command(&full);
    run(&exe, &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-EncodedCommand", &encoded], timeout)
}

/// Base64 of the UTF-16LE script, the form `-EncodedCommand` takes.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn encoded_command(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    base64(&bytes)
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

/// A PowerShell single-quoted string literal (`'` doubled), safe for any path.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''").replace(['\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'], "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // "a" as UTF-16LE is 61 00.
        assert_eq!(encoded_command("a"), "YQA=");
    }

    #[test]
    fn ps_quote_doubles_quotes() {
        assert_eq!(ps_quote("C:\\a'b"), "'C:\\a''b'");
        assert_eq!(ps_quote("x\u{2019}y"), "'x''y'");
    }

    #[cfg(unix)]
    #[test]
    fn a_slow_process_is_stopped_at_its_timeout() {
        let t = Instant::now();
        assert!(run("/bin/sleep", &["5"], Duration::from_millis(300)).is_err());
        assert!(t.elapsed() < Duration::from_secs(3));
        let o = run("/bin/echo", &["hi"], Duration::from_secs(5)).unwrap();
        assert!(o.ok() && o.stdout.trim() == "hi");
    }
}
