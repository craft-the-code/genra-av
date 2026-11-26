# Genra AV roadmap

Long game, small steps. Each phase ends with something a real person can use, and with an exit
check that says whether to go on. Q1–Q12 in [docs/ux/README.md](docs/ux/README.md) were answered on 26/11/2026; dates come with the
screen mock-ups.

## P0 Engine prototype (done 26/11/2026)

- Rust core: OLE2/OOXML reader, MS-OVBA decompression, VBA module extraction.
- Signed JSON rule packs (Ed25519), rollback-safe version, allow list and rule kill switch.
- Built-in macro heuristics; first rules: Kangatang (2), generic downloader.
- CLI `genra-av scan`, `genra-av rules keygen|sign|verify`.
- Name, mark, app icon, tray icons ([docs/brand.md](docs/brand.md)).

Exit: a real Kangatang sample is caught as malware; clean `.docx` stays OK; a tampered pack is refused. ✅

## P1 UX locked, then the first thing people touch

1. Mock-ups of the six screens in `docs/ux/README.md` (tokens in `docs/design/tokens.md`), reviewed
   before any UI code. Question series answered 26/11.
2. **Web file check**: the same core compiled to WebAssembly. Drop a file in the browser, it is
   checked on the device and never uploaded. Zero install, every OS, a link people can pass on Zalo.
3. Server-side use: the core as a library/CLI for upload scanners in other products, next to ClamAV.
4. Clean a document: write a copy without the VBA project (and without the worm's module sheet).
5. Corpus: 50+ real macro samples and 500+ clean office files; false positives tracked per pack.
6. Fuzzing (`cargo fuzz`) on the OLE and VBA parsers.

Exit: 0 false positives on the clean corpus; people in 2 offices use the web check unprompted.
Open source since 26/11/2026: Apache-2.0, public on GitHub (moved up from P1, Hoan).

## P2 Desktop app (Windows first): the repair experience

The core experience is "Dọn giúp tôi" without breaking anything (docs/ux, core experience).

- `genra-guard` background process (Rust, no UI) + Tauri 2 window opened on demand (ADR 0003);
  Windows spike on a 4 GB PC checks the memory numbers first.
- Scan on demand, drag and drop, right-click "Kiểm tra bằng Genra AV".
- Watch the folders threats arrive in (Downloads, Zalo received files, XLSTART, USB drives) with
  OS file notifications, no kernel driver.
- Repair: remove persistence (XLSTART worm workbooks, Office startup add-ins), with undo for 30 days.
- Health card: Windows Defender on and up to date, Office macro setting, Windows updates.
- Update channel live (ADR 0002): hourly pack check over a CDN, staged rollout, kill switch.
- Signed installers: Windows Authenticode, macOS Developer ID + notarisation; app auto-update.

Exit: install-to-first-scan under 1 minute on an office PC; a pack reaches 90% of clients in 6 hours.

## P3 Wider protection

- YARA-X rules for byte patterns beyond macros (scripts, LNK, HTA, malicious PDF, archives).
- Public hash feeds (e.g. MalwareBazaar) folded into packs, each feed's licence checked first.
- macOS and Linux desktop builds; Android "check a file shared to Genra AV".
- Opt-in report of hashes of detected files (never content), to see which families spread where.

## P4 Long term

- Real-time protection on Windows (minifilter driver, Microsoft signing), only if P2 shows the
  watch-folder approach misses threats in practice.
- Windows Security Center registration (Microsoft Virus Initiative membership).
- Independent lab results (AV-Comparatives / AV-TEST) before claiming parity with paid products.

## Not doing

- Scanning the whole disk for every malware family: Defender does that already.
- Collecting files from users without an explicit yes per file.
