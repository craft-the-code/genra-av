//! Genra AV desktop shell. The window only asks; the Rust side reads files, runs the core scanner
//! and talks to the backend. Nothing leaves the machine except an explicit "báo nhầm" report.

use genra_av_core::rules::Pack;
use serde::Serialize;
use std::path::PathBuf;
use tauri::{Manager, State};

/// Files above this are not read: Office documents worth scanning are far smaller (same cap as the CLI).
const MAX_FILE: u64 = 200 * 1024 * 1024;
const REPORT_URL: &str = "https://genra-api.craftthecode.dev/v1/report";
const MAX_NOTE: usize = 2000;

/// The pack that ships inside the app.
// TODO(ADR 0002): verify the bundled pack's Ed25519 signature (`Pack::verified`) once release
// builds embed the publishing key; until then it is parsed unsigned, like `--unsigned` in the CLI.
static BUNDLED_PACK: &[u8] = include_bytes!("../../../rules/base.json");

struct Rules(Pack);

#[derive(Serialize)]
struct RulesInfo {
    version: u64,
    published: String,
    rules: usize,
}

#[derive(Serialize)]
struct ScanResult {
    name: String,
    path: String,
    size: u64,
    report: genra_av_core::Report,
}

#[tauri::command]
fn rules_info(rules: State<'_, Rules>) -> RulesInfo {
    RulesInfo { version: rules.0.version, published: rules.0.published.clone(), rules: rules.0.rules.len() }
}

/// Reads the file (never opens or runs it) and scans the bytes with the bundled pack.
#[tauri::command]
async fn scan_file(path: String, rules: State<'_, Rules>) -> Result<ScanResult, String> {
    let pack = rules.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let p = PathBuf::from(&path);
        let meta = std::fs::metadata(&p).map_err(|e| format!("read: {e}"))?;
        if !meta.is_file() {
            return Err("not_a_file".into());
        }
        if meta.len() > MAX_FILE {
            return Err("too_large".into());
        }
        let bytes = std::fs::read(&p).map_err(|e| format!("read: {e}"))?;
        let report = genra_av_core::scan(&bytes, Some(&pack));
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        Ok(ScanResult { name, path, size: meta.len(), report })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// A file passed on the command line (`genra-av-app <file>`, later "Open with Genra AV"):
/// the window checks it as soon as it opens.
#[tauri::command]
fn launch_path() -> Option<String> {
    std::env::args_os().skip(1).map(PathBuf::from).find(|p| p.is_file()).map(|p| p.to_string_lossy().into_owned())
}

/// Shows the file in Finder / Explorer; the file itself is not opened.
#[tauri::command]
fn reveal(path: String) -> Result<(), String> {
    tauri_plugin_opener::reveal_item_in_dir(path).map_err(|e| e.to_string())
}

/// A random id per install, so the backend can rate-limit and group reports. It says nothing
/// about the user and is stored only in the app data folder.
fn install_id(app: &tauri::AppHandle) -> Result<String, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let file = dir.join("install_id");
    if let Ok(s) = std::fs::read_to_string(&file) {
        if let Ok(id) = uuid::Uuid::parse_str(s.trim()) {
            return Ok(id.hyphenated().to_string());
        }
    }
    let id = uuid::Uuid::new_v4().hyphenated().to_string();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(&file, &id).map_err(|e| e.to_string())?;
    Ok(id)
}

fn os_name() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        _ => "linux",
    }
}

/// "Tệp này an toàn, báo nhầm": sends the hash, the rule id and the user's note. Never the file.
#[tauri::command]
async fn report_false_positive(
    app: tauri::AppHandle,
    sha256: String,
    rule_id: Option<String>,
    note: Option<String>,
) -> Result<(), String> {
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid sha256".into());
    }
    let note = note.map(|n| n.trim().chars().take(MAX_NOTE).collect::<String>()).filter(|n| !n.is_empty());
    let body = serde_json::json!({
        "kind": "false_positive",
        "sha256": sha256.to_ascii_lowercase(),
        "rule_id": rule_id,
        "app_version": env!("CARGO_PKG_VERSION"),
        "os": os_name(),
        "install_id": install_id(&app)?,
        "note": note,
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("genra-av-app/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client.post(REPORT_URL).json(&body).send().await.map_err(|e| format!("network: {e}"))?;
    let status = res.status();
    if status.is_success() {
        Ok(())
    } else {
        let text = res.text().await.unwrap_or_default();
        Err(format!("{status}: {}", text.chars().take(300).collect::<String>()))
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let pack = Pack::parse(BUNDLED_PACK).expect("bundled rules/base.json is valid");
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Rules(pack))
        .invoke_handler(tauri::generate_handler![rules_info, launch_path, scan_file, reveal, report_false_positive])
        .run(tauri::generate_context!())
        .expect("error while running Genra AV");
}
