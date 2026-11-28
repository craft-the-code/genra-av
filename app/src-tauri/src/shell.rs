//! "Kiểm tra bằng Genra AV" in the Explorer right-click menu (J1: one action for a file received
//! on Zalo). Windows only, per user: `HKCU\Software\Classes\*\shell\GenraAV`, written by the app
//! itself (no admin rights, so the per-user NSIS install and the MSI both get it) and removed by
//! the NSIS uninstaller (`windows/hooks.nsh`) or by switching it off in Cài đặt. The command
//! starts Genra with the file; a Genra already running takes the file instead (single instance).

/// The verb's key name under `*\shell`. Never change it: the uninstaller deletes this name.
#[cfg(windows)]
const KEY: &str = r"Software\Classes\*\shell\GenraAV";

/// The menu label in the window's language.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn label(lang: &str) -> &'static str {
    if lang == "en" {
        "Check with Genra AV"
    } else {
        "Kiểm tra bằng Genra AV"
    }
}

/// Whether this system has the menu at all.
pub const SUPPORTED: bool = cfg!(windows);

/// The command Explorer runs: this program, with the file quoted.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn command_line(exe: &std::path::Path) -> String {
    format!("\"{}\" \"%1\"", exe.display())
}

/// Adds or refreshes the menu entry (`on`), or removes it. Idempotent; run at each start so a
/// moved or updated program keeps a working entry.
#[cfg(windows)]
pub fn sync(on: bool, lang: &str) -> anyhow::Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if !on {
        return match hkcu.delete_subkey_all(KEY) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        };
    }
    let exe = std::env::current_exe()?;
    let (verb, _) = hkcu.create_subkey(KEY)?;
    verb.set_value("MUIVerb", &label(lang))?;
    verb.set_value("Icon", &format!("\"{}\",0", exe.display()))?;
    let (cmd, _) = verb.create_subkey("command")?;
    cmd.set_value("", &command_line(&exe))?;
    Ok(())
}

#[cfg(not(windows))]
pub fn sync(_on: bool, _lang: &str) -> anyhow::Result<()> {
    Ok(())
}

/// The file a second launch was started for ("Kiểm tra bằng Genra AV" while Genra is open):
/// the first argument after the program that is an existing file, read relative to `cwd`.
pub fn file_arg(argv: &[String], cwd: &str) -> Option<std::path::PathBuf> {
    argv.iter().skip(1).map(|a| std::path::Path::new(cwd).join(a)).find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_quotes_program_and_file() {
        assert_eq!(command_line(std::path::Path::new("C:/Program Files/Genra AV/genra-av.exe")), "\"C:/Program Files/Genra AV/genra-av.exe\" \"%1\"");
    }

    #[test]
    fn file_arg_skips_program_and_flags() {
        let dir = std::env::temp_dir().join(format!("genra-shell-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.xls"), b"x").unwrap();
        let cwd = dir.to_string_lossy().into_owned();
        let argv = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(file_arg(&argv(&["genra-av.exe", "--flag", "a.xls"]), &cwd), Some(dir.join("a.xls")));
        assert_eq!(file_arg(&argv(&["a.xls"]), &cwd), None, "argv[0] is the program");
        assert_eq!(file_arg(&argv(&["genra-av.exe", "missing.xls"]), &cwd), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn labels() {
        assert_eq!(label("vi"), "Kiểm tra bằng Genra AV");
        assert_eq!(label("en"), "Check with Genra AV");
    }
}
