# Changelog

All notable changes are listed here, newest first. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/). Each GitHub Release copies its section.

## [Unreleased]

## [0.1.2] - 2026-11-26

Pre-release: Windows installers are not code-signed yet; macOS is signed and notarised.

### Added
- "Quét tuỳ chọn": scan the whole computer (every drive and USB stick, leaving out Windows and
  installed programs but not Office's startup folder) or several folders picked at once, each
  removable from the list before the scan starts.
- A "Dừng" button on every scan. A stopped scan says so and is never reported as "Máy an toàn".
- The quick scan also walks Pictures, Videos and, on Windows, the OneDrive copies of the usual folders.

### Changed
- A folder scan or a stopped scan keeps what earlier scans found in "Tệp tìm thấy".
- App updates reach official releases only; pre-releases are installed by hand.

## [0.1.1] - 2026-11-26

Pre-release: Windows installers are not code-signed yet; macOS is signed and notarised.

### Added
- Quick scan lists every file it found ("Tệp tìm thấy"), each one press from its own result.
  The list is kept with the scan in history, so after a restart each file can be checked again
  on its own ("Kiểm tra lại") without scanning the whole computer.

### Fixed
- Release: the macOS dmg, already signed by Tauri, is re-signed with `--force` before notarising.

## [0.1.0] - 2026-11-26

First pre-release: Windows installers are not code-signed yet; macOS is signed and notarised.

### Added
- App updates: the app checks the signed GitHub release feed and offers a one-press update.
- Windows smoke test checklist (`docs/testing/windows-smoke.md`) run before a pre-release is promoted.
- Engine: OLE2/OOXML reader, MS-OVBA decompression, VBA module extraction.
- Signed rule packs (Ed25519) with an allow list and rule kill switch. Signed packs must carry
  `expires` (refused once past it), and the highest accepted version is kept in the data folder so
  an older pack, or another pack with the same version, is refused.
- Built-in macro heuristics; rules for the Kangatang Excel worm and generic macro downloaders.
- CLI: `genra-av scan`, `genra-av clean`, `genra-av rules keygen|sign|verify`.
- Quick scan of the places threats arrive (Downloads, Desktop, Documents, Zalo received files, Excel
  startup folders, removable drives), with a verdict cache: second run reads only changed files.
  The cache is tied to the rules and hash lists it was checked with; new lists are applied from the
  stored SHA-256 without reading files again. Every file in XLSTART is read, whatever its extension.
- Hash reputation: sorted binary hash lists shipped beside the signed pack, covered by its signature.
  A match on a public feed is `suspicious` and never quarantines on its own; only a list marked
  `trusted` can. A missing or damaged list warns and the scan goes on with rules only.
- Quarantine: encoded storage under a random id, refuses a file changed since the scan or a link,
  rolls back if the original cannot be removed; restore never overwrites or writes through a link;
  30-day expiry.
- CLI: `genra-av quick-scan [--quarantine]`, `genra-av quarantine list|restore|purge`, `genra-av hashes build`.
- CI rule pack (`.github/workflows/rule-pack.yml`): MalwareBazaar hashes merged every 6 hours, built in
  a read-only job, signed with openssl in the protected `rule-pack` environment; versioned hash lists,
  14-day expiry, refuses to shrink the list. CLI: `rules verify --any-expiry`, `hashes dump`.
- Engine: `clean` writes a macro-free copy of an Office file (OOXML → .xlsx/.docx/.pptx; .xls and .doc
  without their VBA storage; .xls also without OBJPROJ and "Visual Basic module" sheets). VBA parts
  are found by relationship type, content type and content, not by name; remote templates are removed;
  Excel 4.0 macro sheets, auto-run names, macro add-ins and encrypted workbooks are refused.
- Engine: zip input is bounded (256 MB decompressed, 20,000 entries, no duplicate or overlapping
  entries); anything unreadable is reported as `vba_unreadable`, never as clean.
- Backend at `genra-api.craftthecode.dev`: false-positive / bug reports and VBA-only sample upload.
- Desktop app shell (Tauri 2, `app/`): sidebar with six screens, light/dark/system theme, Vietnamese and
  English; "Kiểm tra tệp" scans a dropped or chosen file with the bundled rules; "báo nhầm" sends a
  false-positive report (hash, rule id, note; never the file). Other screens show "Sắp có" states.
- Desktop app v2: navy sidebar with four places (Tổng quan, Kiểm tra tệp, Máy của bạn, Cài đặt), the
  brand band with one action, "Lịch sử & hoàn tác". Signed rule packs are downloaded on start and every
  6 hours, verified (signature, expiry, version floor, hash-list digests) and swapped in atomically;
  the bundled pack is the fallback. "Dọn sạch giúp tôi" replaces the file with a macro-free copy in
  place, keeps the original in quarantine, re-scans, and undoes in one press. "Quét nhanh máy" runs in
  the background with progress and says when it is waiting for the macOS permission prompt.
  Commands that take a path accept only paths picked, dropped or found by a scan in this session.
- Release workflow (`.github/workflows/release.yml`): a `v<x.y.z>` tag builds the Windows (.exe, .msi),
  universal macOS (.dmg) and Linux (.AppImage, .deb) installers, checks the tag against every version
  in the repo, and publishes a GitHub Release with fixed file names, `SHA256SUMS`, build attestations,
  notes from this file and the updater's `latest.json`. macOS signed and notarised; Windows unsigned
  for the beta. `scripts/bump-version.py` sets the version everywhere (docs/releasing.md).
- `genra_av_core::paths::data_dir()` shared by the CLI and the app (`GENRA_AV_DATA_DIR` overrides it).
- Brand, UX decisions, design tokens and v1 mock-ups (`docs/`).
- Machine repair (`crates/machine`): "Dọn sạch giúp tôi" cleans the machine, not just the file. A
  journal written before every change, one-press undo per repair (refused if a file changed since,
  never overwrites), 30-day expiry. Fixed actions only: replace a file with its verified clean copy
  (original quarantined), quarantine a file, remove a worm from Excel's startup folder, reset Office's
  "enable all macros" (Windows, current user), switch off a user startup item. The plan for a Kangatang
  hit (or a rule with `machine_persistence: xlstart`) also covers XLSTART and other infected workbooks.
  Excel status and a polite close request; health (Defender/Gatekeeper, updates, firewall, Office
  macros); startup items with signatures and verdicts. CLI: `genra-av machine health|startup|plan|
  repair|journal|undo`.
- Desktop app on the machine engine: "Dọn sạch giúp tôi" runs the machine plan (the file, Excel's
  startup folder, other infected workbooks in the quick-scan places) with step progress; one "Hoàn tác"
  undoes the whole journal group. When Excel holds what must change, the app shows "Cần đóng Excel
  trước khi dọn", asks Excel to close on "Đóng Excel giúp tôi", checks every second and carries on by
  itself once Excel is gone. "Máy của bạn" shows real health and startup items ("Sửa giúp tôi" for the
  Office macro setting, "Tắt" for this user's suspicious startup items, both undoable) and the places
  the quick scan covers; read once per session on a background thread. Cài đặt shows the install id
  used in reports, with a copy button. The app's own file-level repair is gone.
- Rules carry an optional `message_en` (old packs still load); every rule in `rules/base.json` has one
  and the built-in heuristics have English text. The app shows it when the window is in English.
- A detected file that sits in Excel's startup folder is moved out of it, not cleaned in place.

### Fixed
- macOS: internal volumes such as Recovery are no longer listed as removable drives.
