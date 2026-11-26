# Changelog

All notable changes are listed here, newest first. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/). Each GitHub Release copies its section.

## [Unreleased]

### Added
- Engine: OLE2/OOXML reader, MS-OVBA decompression, VBA module extraction.
- Signed rule packs (Ed25519) with rollback protection, allow list and rule kill switch.
- Built-in macro heuristics; rules for the Kangatang Excel worm and generic macro downloaders.
- CLI: `genra-av scan`, `genra-av rules keygen|sign|verify`.
- Backend at `genra-api.craftthecode.dev`: false-positive / bug reports and VBA-only sample upload.
- Brand, UX decisions, design tokens and v1 mock-ups (`docs/`).
