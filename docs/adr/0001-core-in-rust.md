# ADR 0001: one detection core in Rust

Status: accepted (Hoan, 26/11/2026). UI shell: Tauri 2 (ADR 0003). Licence: Apache-2.0 (Q9).

## Context

Genra AV must run on Windows first, then macOS, Linux, Android, in the browser and inside other
products' upload scanners. Parsing hostile files is where antivirus engines themselves get
exploited, so the parser must be memory-safe. The team is one maintainer plus contributors.

## Decision

- One core crate in Rust: file parsing, rule evaluation, verdicts. Every surface (CLI, desktop
  app, WebAssembly page, server library) calls the same core, so a rule behaves the same everywhere.
- Parse, never execute: VBA is decompressed and read as text; nothing is handed to Office.
- Do not link libclamav (GPL-2.0). ClamAV can run beside us where it already runs; this keeps the
  licence choice open (Apache-2.0 proposed) and the binary small (1.3 MB today).
- Byte-pattern rules later through YARA-X (Rust, BSD-3), not a home-made pattern language.
- The UI is native per platform and calls the core over a thin binding (Q4); the core has no UI code.

## Consequences

- A WebAssembly build is possible from day one (no C dependency in the core).
- We own the OLE/VBA parsing code and its fuzzing.
- Detection breadth comes from packs and YARA-X rules, not from re-implementing ClamAV.
