# Changelog

All notable changes are listed here, newest first. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/). Each GitHub Release copies its section.

## [Unreleased]

### Added
- Engine: OLE2/OOXML reader, MS-OVBA decompression, VBA module extraction.
- Signed rule packs (Ed25519) with rollback protection, allow list and rule kill switch.
- Built-in macro heuristics; rules for the Kangatang Excel worm and generic macro downloaders.
- CLI: `genra-av scan`, `genra-av rules keygen|sign|verify`.
- Quick scan of the places threats arrive (Downloads, Desktop, Documents, Zalo received files, Excel
  startup folders, removable drives), with a verdict cache: second run reads only changed files.
- Hash reputation: sorted binary hash lists shipped beside the signed pack, covered by its signature.
- Quarantine: encoded storage, restore without overwriting, 30-day expiry.
- CLI: `genra-av quick-scan [--quarantine]`, `genra-av quarantine list|restore|purge`, `genra-av hashes build`.
- Backend at `genra-api.craftthecode.dev`: false-positive / bug reports and VBA-only sample upload.
- Brand, UX decisions, design tokens and v1 mock-ups (`docs/`).
