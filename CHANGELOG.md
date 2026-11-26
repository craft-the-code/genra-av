# Changelog

All notable changes are listed here, newest first. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/). Each GitHub Release copies its section.

## [Unreleased]

### Added
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
- Brand, UX decisions, design tokens and v1 mock-ups (`docs/`).
