//! genra-av: scan files and folders, and manage signed rule packs.
//! Exit code: 0 nothing found, 1 a suspicious or malware finding, 2 an error.

mod machine;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use genra_av_core::quarantine::Quarantine;
use genra_av_core::reputation::{HashList, Reputation};
use genra_av_core::rules::{verifying_key_from_hex, Pack, PackState, Severity};
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
        /// Ask Windows Defender about files Genra calls suspicious, as the app does (Windows,
        /// Defender on). Defender only reports; it does not move the file.
        #[arg(long)]
        defender: bool,
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
    /// Write a macro-free copy of an Office file as <name>.clean.<ext>. The original is not changed.
    Clean {
        input: PathBuf,
        /// Folder for the copy (default: next to the input).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Rule pack tooling for whoever publishes packs.
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Hash list tooling for whoever publishes packs.
    #[command(subcommand)]
    Hashes(HashesCmd),
    /// YARA rule tooling for whoever publishes packs.
    #[command(subcommand)]
    Yara(YaraCmd),
    /// Clean the machine, not just the file: health, startup items, repair plans, journal, undo.
    #[command(subcommand)]
    Machine(machine::MachineCmd),
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
    /// Binary list -> one hex SHA-256 per line on stdout (the CI merges a verified previous list this way).
    Dump { input: PathBuf },
}

#[derive(Subcommand)]
enum YaraCmd {
    /// Compile rule blocks (separated by a `// @genra-rule` line, imports before the first one)
    /// one by one with Genra's engine, in order, and print the names of those it refuses, one per
    /// line. A rule that needs a refused one is refused too. Then compiles the kept set whole.
    Check { input: PathBuf },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// New Ed25519 key pair: <name>.key (keep secret, outside Git) and <name>.pub.
    Keygen { out: PathBuf },
    /// Sign a pack: writes <pack>.sig.
    Sign { pack: PathBuf, #[arg(long)] key: PathBuf },
    /// Check a pack's signature, format, expiry and the hash lists beside it.
    Verify {
        pack: PathBuf,
        #[arg(long)]
        pubkey: PathBuf,
        /// Accept an expired pack or one without `expires` (publishers reading an older pack).
        #[arg(long)]
        any_expiry: bool,
    },
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
        Cmd::Scan { paths, rules, pubkey, unsigned, json, defender } => {
            let pack = load_pack(rules.as_deref(), pubkey.as_deref(), unsigned, true)?;
            let rep = load_reputation(pack.as_ref(), rules.as_deref());
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
                    found |= scan_one(entry.path(), pack.as_ref(), Some(&rep), json, defender);
                }
            }
            Ok(found)
        }
        Cmd::QuickScan { rules, pubkey, unsigned, quarantine, also } => {
            let pack = load_pack(rules.as_deref(), pubkey.as_deref(), unsigned, true)?;
            let rep = load_reputation(pack.as_ref(), rules.as_deref());
            describe(pack.as_ref(), &rep);
            let mut roots = targets::quick_targets();
            let usb = targets::removable_volumes();
            roots.extend(usb.iter().cloned());
            roots.extend(also);
            for r in &roots {
                eprintln!("target: {}", r.display());
            }
            let data = data_dir()?;
            std::fs::create_dir_all(&data)?;
            let cache_path = data.join("scan-cache.json");
            let mut ctx = scanner::Context::new(pack.as_ref(), Some(&rep), scanner::Cache::load(&cache_path));
            let started = std::time::Instant::now();
            // Hidden folders are walked on USB sticks, where worms hide their copies.
            let mut walk = scanner::Walk::quick();
            walk.hidden_ok = &usb;
            let summary = scanner::walk_with(&mut ctx, &roots, &walk, |_| {});
            ctx.cache.save(&cache_path)?;
            eprintln!(
                "seen {} files, read {}, remembered {}, rechecked by hash {}, too large {}, in {:.1} s",
                summary.files_seen, summary.files_read, summary.files_cached, summary.files_rechecked, summary.skipped_large,
                started.elapsed().as_secs_f32()
            );
            let q = if quarantine { Some(Quarantine::open(data.join("quarantine"))?) } else { None };
            let mut hits = summary.hits;
            for hit in &mut hits {
                // A validly signed program is never quarantined on a hash match alone (ADR 0004).
                genra_av_machine::rails::signed_file_rail(&mut hit.report, &hit.path);
                // Windows Defender's opinion on what Genra calls suspicious (ADR 0004, layer 4).
                genra_av_machine::defender::second_opinion(&mut hit.report, &hit.path, pack.as_ref().map(|p| p.disabled.as_slice()).unwrap_or(&[]));
            }
            for hit in &hits {
                print_report(&hit.path, &hit.report);
                // Only a reviewed rule, a heuristic or a trusted hash list moves a file; a match
                // on a public hash feed alone is reported and left in place.
                if let (Some(q), true) = (&q, hit.report.should_quarantine()) {
                    let reason = hit
                        .report
                        .findings
                        .iter()
                        .find(|f| f.severity == Severity::Malware && f.auto_quarantine)
                        .map(|f| f.family.clone())
                        .unwrap_or_default();
                    match q.put(&hit.path, &hit.report.sha256, &reason) {
                        Ok(item) => println!("        → quarantined as {}", item.id),
                        Err(e) => println!("        → could not quarantine: {e:#}"),
                    }
                }
            }
            Ok(!hits.is_empty())
        }
        Cmd::Quarantine(cmd) => {
            let q = Quarantine::open(data_dir()?.join("quarantine"))?;
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
        Cmd::Machine(cmd) => machine::run(cmd),
        Cmd::Hashes(HashesCmd::Dump { input }) => {
            use std::io::Write;
            let bytes = std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            HashList::from_bytes(&bytes)?;
            let mut out = std::io::BufWriter::new(std::io::stdout().lock());
            for d in bytes.as_chunks::<32>().0 {
                writeln!(out, "{}", hex::encode(d))?;
            }
            out.flush()?;
            Ok(false)
        }
        Cmd::Yara(YaraCmd::Check { input }) => {
            let text = std::fs::read_to_string(&input).with_context(|| format!("reading {}", input.display()))?;
            let (refused, kept) = genra_av_core::yara::check_blocks(&text);
            for name in &refused {
                println!("{name}");
            }
            eprintln!("{} rules kept, {} refused", kept, refused.len());
            Ok(false)
        }
        Cmd::Hashes(HashesCmd::Build { input, out }) => {
            let bin = HashList::build_from_text(&std::fs::read_to_string(&input)?)?;
            std::fs::write(&out, &bin)?;
            use sha2::Digest;
            eprintln!("wrote {} ({} hashes), sha256 {}", out.display(), bin.len() / 32, hex::encode(sha2::Sha256::digest(&bin)));
            Ok(false)
        }
        Cmd::Clean { input, out } => {
            let size = std::fs::metadata(&input).with_context(|| format!("reading {}", input.display()))?.len();
            if size > MAX_FILE {
                bail!("{} is over {} MB", input.display(), MAX_FILE / 1024 / 1024);
            }
            let bytes = std::fs::read(&input)?;
            let cleaned = genra_av_core::clean::clean(&bytes)?;
            let ext = cleaned
                .new_extension
                .map(str::to_string)
                .or_else(|| input.extension().map(|e| e.to_string_lossy().into_owned()))
                .unwrap_or_default();
            let stem = input.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let dir = out.unwrap_or_else(|| input.parent().map(Path::to_path_buf).unwrap_or_default());
            let dest = dir.join(format!("{stem}.clean.{ext}"));
            write_new(&dest, &cleaned.bytes)?;
            for r in &cleaned.removed {
                println!("removed  {r}");
            }
            for k in &cleaned.kept {
                println!("kept     {k}");
            }
            println!("wrote    {}", dest.display());
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
        Cmd::Rules(RulesCmd::Verify { pack, pubkey, any_expiry }) => {
            let p = if any_expiry {
                let bytes = std::fs::read(&pack).with_context(|| format!("reading {}", pack.display()))?;
                let key = verifying_key_from_hex(&std::fs::read_to_string(&pubkey)?)?;
                let sig = std::fs::read_to_string(sig_path(&pack)).context("missing <pack>.sig")?;
                Pack::signature_checked(&bytes, &sig, &[key])?
            } else {
                load_pack(Some(&pack), Some(&pubkey), false, false)?.expect("pack given")
            };
            // Strict here: a publisher must not build on a list that does not match its pack.
            let dir = pack.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let rep = Reputation::load(&p, dir)?;
            eprintln!("ok: version {}, {} rules, {} hashes, {} YARA rules, signature valid", p.version, p.rules.len(), rep.entries(), rep.yara().map(|y| y.len()).unwrap_or(0));
            if let Some(e) = rep.yara_error() {
                eprintln!("warning: YARA rules not in use: {e}");
            }
            Ok(false)
        }
    }
}

/// Creates `dest` and writes `bytes`, failing if anything already exists at that path, a
/// dangling symlink included (O_EXCL / CREATE_NEW: no check-then-write race, no following links).
fn write_new(dest: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .with_context(|| format!("{} exists or cannot be created; refusing to overwrite", dest.display()))?;
    f.write_all(bytes).with_context(|| format!("writing {}", dest.display()))?;
    f.sync_all()?;
    Ok(())
}

fn sig_path(pack: &Path) -> PathBuf {
    let mut s = pack.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

/// Loads a pack. A signed pack must verify and be unexpired; with `remember`, it must also be
/// newer than (or identical to) the highest version this install accepted, which is then saved.
fn load_pack(path: Option<&Path>, pubkey: Option<&Path>, unsigned: bool, remember: bool) -> Result<Option<Pack>> {
    let Some(path) = path else { return Ok(None) };
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if unsigned {
        eprintln!("warning: rule pack loaded WITHOUT signature check (--unsigned)");
        return Ok(Some(Pack::parse(&bytes)?));
    }
    let pubkey = pubkey.context("--pubkey is required unless --unsigned")?;
    let key = verifying_key_from_hex(&std::fs::read_to_string(pubkey)?)?;
    let sig = std::fs::read_to_string(sig_path(path)).context("missing <pack>.sig")?;
    let pack = Pack::verified(&bytes, &sig, &[key])?;
    if remember {
        let data = data_dir()?;
        std::fs::create_dir_all(&data)?;
        PackState::accept(&data.join("pack-state.json"), &pack, &bytes)?;
    }
    Ok(Some(pack))
}

/// Where Genra keeps its cache, quarantine and pack state; the desktop app uses the same place.
fn data_dir() -> Result<PathBuf> {
    genra_av_core::paths::data_dir()
}

/// Hash lists sit next to the pack JSON; the (verified) pack vouches for their digests. A list
/// that is missing or does not match (half-finished download, publish in progress) does not
/// stop the scan: it warns and goes on with rules and heuristics only.
fn load_reputation(pack: Option<&Pack>, rules: Option<&Path>) -> Reputation {
    let loaded = match (pack, rules.and_then(|r| r.parent())) {
        (Some(p), Some(dir)) if !p.hash_sets.is_empty() || p.yara.is_some() => Reputation::load(p, if dir.as_os_str().is_empty() { Path::new(".") } else { dir }),
        _ => Ok(Reputation::default()),
    };
    loaded.unwrap_or_else(|e| {
        eprintln!("warning: hash lists not loaded ({e:#}); scanning with rules and heuristics only");
        Reputation::default()
    })
}

fn describe(pack: Option<&Pack>, rep: &Reputation) {
    match pack {
        Some(p) => {
            let yara = rep.yara().map(|y| y.len()).unwrap_or(0);
            eprintln!("rules: version {} ({} rules, {} known-bad hashes, {} YARA rules)", p.version, p.rules.len(), rep.entries(), yara);
            if let Some(e) = rep.yara_error() {
                eprintln!("warning: YARA rules not in use ({e}); hash lists and the other checks are");
            }
        }
        None => eprintln!("rules: none loaded, built-in heuristics only"),
    }
}

fn scan_one(path: &Path, pack: Option<&Pack>, rep: Option<&Reputation>, json: bool, defender: bool) -> bool {
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
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut report = genra_av_core::scan_named(&name, &bytes, pack, rep);
    if defender {
        if let Ok(abs) = std::path::absolute(path) {
            genra_av_machine::defender::second_opinion(&mut report, &abs, pack.map(|p| p.disabled.as_slice()).unwrap_or(&[]));
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_hash_list_does_not_stop_the_scan() {
        let pack = Pack::parse(br#"{"format":1,"version":1,"published":"x","hash_sets":[{"file":"missing.bin","sha256":"00","family":"f","source":"s"}]}"#).unwrap();
        let rep = load_reputation(Some(&pack), Some(Path::new("/nonexistent/pack.json")));
        assert_eq!(rep.entries(), 0);
    }
}

#[cfg(test)]
mod clean_tests {
    use super::*;

    #[test]
    fn write_new_never_overwrites_or_follows_links() {
        let dir = std::env::temp_dir().join(format!("genra-av-write-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let existing = dir.join("a.clean.xlsx");
        std::fs::write(&existing, b"keep").unwrap();
        assert!(write_new(&existing, b"new").is_err());
        assert_eq!(std::fs::read(&existing).unwrap(), b"keep");
        #[cfg(unix)]
        {
            // A dangling symlink: `exists()` says false, but writing through it would create the
            // link's target elsewhere.
            let target = dir.join("elsewhere");
            let link = dir.join("b.clean.xlsx");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(!link.exists());
            assert!(write_new(&link, b"x").is_err());
            assert!(!target.exists());
        }
        let fresh = dir.join("c.clean.xlsx");
        write_new(&fresh, b"ok").unwrap();
        assert_eq!(std::fs::read(&fresh).unwrap(), b"ok");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
