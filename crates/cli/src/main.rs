//! genra-av: scan files and folders, and manage signed rule packs.
//! Exit code: 0 nothing found, 1 a suspicious or malware finding, 2 an error.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use genra_av_core::rules::{verifying_key_from_hex, Pack, Severity};
use std::path::{Path, PathBuf};

/// Files above this are skipped: Office documents worth scanning are far smaller.
const MAX_FILE: u64 = 200 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "genra-av", version, about = "Genra AV: Office macro and document threat scanner")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan files or folders (recursively). Read-only: nothing is opened in Office, moved or changed.
    Scan {
        paths: Vec<PathBuf>,
        /// Rule pack JSON; its signature is read from <pack>.sig.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Trusted public key (hex) for --rules. Release builds embed theirs.
        #[arg(long)]
        pubkey: Option<PathBuf>,
        /// Load --rules without a signature. Development only.
        #[arg(long)]
        unsigned: bool,
        /// One JSON report per line instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Rule pack tooling for whoever publishes packs.
    #[command(subcommand)]
    Rules(RulesCmd),
}

#[derive(Subcommand)]
enum RulesCmd {
    /// New Ed25519 key pair: <name>.key (keep secret, outside Git) and <name>.pub.
    Keygen { out: PathBuf },
    /// Sign a pack: writes <pack>.sig.
    Sign { pack: PathBuf, #[arg(long)] key: PathBuf },
    /// Check a pack's signature and format.
    Verify { pack: PathBuf, #[arg(long)] pubkey: PathBuf },
}

fn main() {
    match run() {
        Ok(found) => std::process::exit(if found { 1 } else { 0 }),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<bool> {
    match Cli::parse().cmd {
        Cmd::Scan { paths, rules, pubkey, unsigned, json } => {
            let pack = load_pack(rules.as_deref(), pubkey.as_deref(), unsigned)?;
            if let Some(p) = &pack {
                eprintln!("rules: version {} ({} rules)", p.version, p.rules.len());
            } else {
                eprintln!("rules: none loaded, built-in heuristics only");
            }
            if paths.is_empty() {
                bail!("give at least one file or folder");
            }
            let mut found = false;
            for root in &paths {
                for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    found |= scan_one(entry.path(), pack.as_ref(), json);
                }
            }
            Ok(found)
        }
        Cmd::Rules(RulesCmd::Keygen { out }) => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("no system randomness: {e}"))?;
            let sk = SigningKey::from_bytes(&seed);
            let key = out.with_extension("key");
            let public = out.with_extension("pub");
            if key.exists() {
                bail!("{} exists; refusing to overwrite a signing key", key.display());
            }
            std::fs::write(&key, hex::encode(sk.to_bytes()))?;
            std::fs::write(&public, hex::encode(sk.verifying_key().to_bytes()))?;
            eprintln!("wrote {} (secret) and {}", key.display(), public.display());
            Ok(false)
        }
        Cmd::Rules(RulesCmd::Sign { pack, key }) => {
            let bytes = std::fs::read(&pack)?;
            Pack::parse(&bytes)?;
            let seed: [u8; 32] = hex::decode(std::fs::read_to_string(&key)?.trim())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("key is not 32 bytes"))?;
            let sig = SigningKey::from_bytes(&seed).sign(&bytes);
            let out = sig_path(&pack);
            std::fs::write(&out, hex::encode(sig.to_bytes()))?;
            eprintln!("wrote {}", out.display());
            Ok(false)
        }
        Cmd::Rules(RulesCmd::Verify { pack, pubkey }) => {
            let p = load_pack(Some(&pack), Some(&pubkey), false)?.expect("pack given");
            eprintln!("ok: version {}, {} rules, signature valid", p.version, p.rules.len());
            Ok(false)
        }
    }
}

fn sig_path(pack: &Path) -> PathBuf {
    let mut s = pack.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

fn load_pack(path: Option<&Path>, pubkey: Option<&Path>, unsigned: bool) -> Result<Option<Pack>> {
    let Some(path) = path else { return Ok(None) };
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if unsigned {
        eprintln!("warning: rule pack loaded WITHOUT signature check (--unsigned)");
        return Ok(Some(Pack::parse(&bytes)?));
    }
    let pubkey = pubkey.context("--pubkey is required unless --unsigned")?;
    let key = verifying_key_from_hex(&std::fs::read_to_string(pubkey)?)?;
    let sig = std::fs::read_to_string(sig_path(path)).context("missing <pack>.sig")?;
    Ok(Some(Pack::verified(&bytes, &sig, &[key])?))
}

fn scan_one(path: &Path, pack: Option<&Pack>, json: bool) -> bool {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size > MAX_FILE {
        if !json {
            println!("SKIP  {} (over {} MB)", path.display(), MAX_FILE / 1024 / 1024);
        }
        return false;
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            return false;
        }
    };
    let report = genra_av_core::scan(&bytes, pack);
    let bad = report.verdict.is_some_and(|v| v >= Severity::Suspicious);
    if json {
        let mut v = serde_json::to_value(&report).unwrap_or_default();
        v["path"] = serde_json::Value::String(path.display().to_string());
        println!("{v}");
        return bad;
    }
    let label = match report.verdict {
        Some(Severity::Malware) => "MALWARE",
        Some(Severity::Suspicious) => "SUSPECT",
        Some(Severity::Info) => "INFO   ",
        None => "OK     ",
    };
    println!("{label} {}", path.display());
    for f in &report.findings {
        println!("        [{}] {}: {}", f.rule, f.family, f.message_vi);
    }
    if !report.vba_modules.is_empty() {
        let names: Vec<_> = report.vba_modules.iter().map(|m| format!("{} ({} B)", m.name, m.bytes)).collect();
        println!("        VBA modules: {}", names.join(", "));
    }
    bad
}
