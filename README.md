<p align="center"><img src="assets/brand/logo-light.svg" width="420" alt="Genra AV"></p>

# Genra AV

A free scanner for the threats Vietnamese offices and families actually receive: Office documents
with macro worms (Kangatang and its kind), downloader macros, and the files passed around on Zalo,
email and USB sticks. It sits next to Windows Defender, not in its place.

Status: **building v0.1.** The engine and command line work; the desktop app is in progress.

Download: installers for Windows (`Genra-AV-Setup.exe`, `Genra-AV.msi`), macOS (`Genra-AV.dmg`) and
Linux (`Genra-AV.AppImage`, `genra-av.deb`) are on [GitHub Releases](https://github.com/craft-the-code/genra-av/releases),
each with `SHA256SUMS` and build attestations. 0.x versions are pre-releases; the beta's Windows
installer is unsigned. How releases are made: [docs/releasing.md](docs/releasing.md).
UX decisions, tokens and mock-ups: [docs/ux/README.md](docs/ux/README.md). Release plan:
[docs/release-plan.md](docs/release-plan.md).

## Try it

```bash
cargo build --release
./target/release/genra-av scan <file-or-folder>                                 # built-in heuristics only
./target/release/genra-av scan --rules rules/base.json --unsigned <path>       # dev: unsigned pack
./target/release/genra-av quick-scan                                           # Downloads, Desktop, Documents, Zalo, USB…
./target/release/genra-av quarantine list
```

Exit code `0` nothing found, `1` suspicious or malware, `2` error. `--json` prints one report per line.

Desktop app (Tauri 2; needs Node 20+ and the Tauri system prerequisites):

```bash
cd app && npm install
npm run tauri dev                      # opens the window; drop a file on "Kiểm tra tệp"
npx tauri build --bundles app          # release bundle under target/release/bundle/
```

## How it is built

- `crates/core` reads files without running them: OLE2 (`.xls/.doc/.ppt`) and OOXML zips
  (`.xlsm/.docm`, renamed `.xlsx`), VBA projects decompressed per [MS-OVBA].
- Detection lives in **rule packs** (`rules/*.json`), signed with Ed25519. A new threat ships as a
  new pack in minutes; the app is not updated. See [ADR 0002](docs/adr/0002-signed-rule-packs.md).
- Built-in heuristics (an auto-run macro that reaches outside the file) work with no pack at all.

Plan: [ROADMAP.md](ROADMAP.md) and the big picture in [docs/strategy.md](docs/strategy.md). Decisions:
[docs/adr](docs/adr). Name and logo: [docs/brand.md](docs/brand.md). Changes: [CHANGELOG.md](CHANGELOG.md).
Security reports: [SECURITY.md](SECURITY.md).

## Samples

Live malware never enters this repository (`.gitignore` blocks `samples/`). Keep samples in an
encrypted archive outside the repo (password `infected` by convention) and test with a path.

## Licence

Apache License 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). Copyright © 2026 Hoan Le and contributors.

Contributions are welcome under the same licence. Please never attach live malware to an issue or
pull request; describe the sample and share its SHA-256 instead.
