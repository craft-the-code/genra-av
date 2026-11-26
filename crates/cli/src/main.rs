//! genra-av: scan files and folders, and manage signed rule packs.
//! Exit code: 0 nothing found, 1 a suspicious or malware finding, 2 an error.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use genra_av_core::quarantine::Quarantine;
use genra_av_core::reputation::{HashList, Reputation};
use genra_av_core::rules::{verifying_key_from_hex, Pack, Severity};
use genra_av_core::{scanner, targets};
use std::path::{Path, PathBuf};

/// Files above this are skipped: Office documents worth scanning are far smaller.
const MAX_FILE: u64 = 200 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "genra-av", version, about = "Genra AV: free antivirus scanner")]
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
    /// Scan the places threats arrive: Downloads, Desktop, Documents, Zalo received files,
    /// Excel startup folders and removable drives. Remembers clean files between runs.
    QuickScan {
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long)]
        pubkey: Option<PathBuf>,
        #[arg(long)]
        unsigned: bool,
        /// Move files found to be malware into quarantine (restorable for 30 days).
        #[arg(long)]
        quarantine: bool,
        /// Also scan these folders.
        #[arg(long = "also")]
        also: Vec<PathBuf>,
    },
    /// Quarantined files: list, restore, purge expired.
    #[command(subcommand)]
    Quarantine(QuarantineCmd),
    /// Rule pack tooling for whoever publishes packs.
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Hash list tooling for whoever publishes packs.
    #[command(subcommand)]
    Hashes(HashesCmd),
}

#[derive(Subcommand)]
enum QuarantineCmd {
    List,
    Restore { id: String },
    /// Delete items older than 30 days.
    Purge,
}

#[derive(Subcommand)]
enum HashesCmd {
    /// Text (one hex SHA-256 per line) -> sorted binary list for a pack; prints its SHA-256.
    Build { input: PathBuf, out: PathBuf },
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
            let rep = load_reputation(pack.as_ref(), rules.as_deref())?;
            describe(pack.as_ref(), &rep);
            if paths.is_empty() {
                bail!("give at least one file or folder");
            }
            let mut found = false;
            for root in &paths {
                for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    found |= scan_one(entry.path(), pack.as_ref(), Some(&rep), json);
                }
            }
            Ok(found)
        }
        Cmd::QuickScan { rules, pubkey, unsigned, quarantine, also } => {
            let pack = load_pack(rules.as_deref(), pubkey.as_deref(), unsigned)?;
            let rep = load_reputation(pack.as_ref(), rules.as_deref())?;
            describe(pack.as_ref(), &rep);
            let mut roots = targets::quick_targets();
            roots.extend(targets::removable_volumes());
            roots.extend(also);
            for r in &roots {
                eprintln!("target: {}", r.display());
            }
            let data = data_dir();
            std::fs::create_dir_all(&data)?;
            let cache_path = data.join("scan-cache.json");
            let mut ctx = scanner::Context { pack: pack.as_ref(), reputation: Some(&rep), cache: scanner::Cache::load(&cache_path) };
            let started = std::time::Instant::now();
            let summary = scanner::walk(&mut ctx, &roots, |_| {});
            ctx.cache.save(&cache_path)?;
            eprintln!(
                "seen {} files, read {}, remembered {}, too large {}, in {:.1} s",
                summary.files_seen, summary.files_read, summary.files_cached, summary.skipped_large,
                started.elapsed().as_secs_f32()
            );
            let q = if quarantine { Some(Quarantine::open(data.join("quarantine"))?) } else { None };
            for hit in &summary.hits {
                print_report(&hit.path, &hit.report);
                if let (Some(q), Some(Severity::Malware)) = (&q, hit.report.verdict) {
                    let reason = hit.report.findings.first().map(|f| f.family.clone()).unwrap_or_default();
                    match q.put(&hit.path, &reason) {
                        Ok(item) => println!("        → quarantined as {}", item.id),
                        Err(e) => println!("        → could not quarantine: {e:#}"),
                    }
                }
            }
            Ok(!summary.hits.is_empty())
        }
        Cmd::Quarantine(cmd) => {
            let q = Quarantine::open(data_dir().join("quarantine"))?;
            match cmd {
                QuarantineCmd::List => {
                    for i in q.list()? {
                        println!("{}  {}  {}  ({} B, {})", i.id, i.reason, i.original_path.display(), i.size, &i.sha256[..16]);
                    }
                }
                QuarantineCmd::Restore { id } => println!("restored to {}", q.restore(&id)?.display()),
                QuarantineCmd::Purge => println!("deleted {} expired item(s)", q.purge_expired()?),
            }
            Ok(false)
        }
        Cmd::Hashes(HashesCmd::Build { input, out }) => {
            let bin = HashList::build_from_text(&std::fs::read_to_string(&input)?)?;
            std::fs::write(&out, &bin)?;
            use sha2::Digest;
            eprintln!("wrote {} ({} hashes), sha256 {}", out.display(), bin.len() / 32, hex::encode(sha2::Sha256::digest(&bin)));
            Ok(false)
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

/// Where Genra keeps its cache and quarantine; the desktop app uses the same place.
fn data_dir() -> PathBuf {
    let home = || std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).unwrap_or_default();
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(home).join("Genra AV")
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support/Genra AV")
    } else {
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home().join(".local/share")).join("genra-av")
    }
}

/// Hash lists sit next to the pack JSON; the (verified) pack vouches for their digests.
fn load_reputation(pack: Option<&Pack>, rules: Option<&Path>) -> Result<Reputation> {
    match (pack, rules.and_then(|r| r.parent())) {
        (Some(p), Some(dir)) if !p.hash_sets.is_empty() => Reputation::load(p, if dir.as_os_str().is_empty() { Path::new(".") } else { dir }),
        _ => Ok(Reputation::default()),
    }
}

fn describe(pack: Option<&Pack>, rep: &Reputation) {
    match pack {
        Some(p) => eprintln!("rules: version {} ({} rules, {} known-bad hashes)", p.version, p.rules.len(), rep.entries()),
        None => eprintln!("rules: none loaded, built-in heuristics only"),
    }
}

fn scan_one(path: &Path, pack: Option<&Pack>, rep: Option<&Reputation>, json: bool) -> bool {
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
    let report = genra_av_core::scan_with(&bytes, pack, rep);
    let bad = report.verdict.is_some_and(|v| v >= Severity::Suspicious);
    if json {
        let mut v = serde_json::to_value(&report).unwrap_or_default();
        v["path"] = serde_json::Value::String(path.display().to_string());
        println!("{v}");
        return bad;
    }
    print_report(path, &report);
    bad
}

fn print_report(path: &Path, report: &genra_av_core::Report) {
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
}
