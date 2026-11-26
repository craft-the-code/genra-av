<p align="center"><img src="assets/brand/logo-light.svg" width="420" alt="Genra AV"></p>

# Genra AV

A free scanner for the threats Vietnamese offices and families actually receive: Office documents
with macro worms (Kangatang and its kind), downloader macros, and the files passed around on Zalo,
email and USB sticks. It sits next to Windows Defender, not in its place.

Status: **P0, engine prototype.** Command line only. The UI is designed first
([docs/ux/README.md](docs/ux/README.md)); no UI code until its questions are answered.
Private for now; it opens up once it is good enough (see Licence).

## Try it

```bash
cargo build --release
./target/release/genra-av scan <file-or-folder>                                 # built-in heuristics only
./target/release/genra-av scan --rules rules/base.json --unsigned <path>       # dev: unsigned pack
```

Exit code `0` nothing found, `1` suspicious or malware, `2` error. `--json` prints one report per line.

## How it is built

- `crates/core` reads files without running them: OLE2 (`.xls/.doc/.ppt`) and OOXML zips
  (`.xlsm/.docm`, renamed `.xlsx`), VBA projects decompressed per [MS-OVBA].
- Detection lives in **rule packs** (`rules/*.json`), signed with Ed25519. A new threat ships as a
  new pack in minutes; the app is not updated. See [ADR 0002](docs/adr/0002-signed-rule-packs.md).
- Built-in heuristics (an auto-run macro that reaches outside the file) work with no pack at all.

Plan: [ROADMAP.md](ROADMAP.md). Decisions: [docs/adr](docs/adr). Name and logo: [docs/brand.md](docs/brand.md).

## Samples

Live malware never enters this repository (`.gitignore` blocks `samples/`). Keep samples in an
encrypted archive outside the repo (password `infected` by convention) and test with a path.

## Licence

Copyright © 2026 Hoan Le. All rights reserved for now (see [LICENSE](LICENSE)).
It will be released under Apache-2.0 once P1 is done.
