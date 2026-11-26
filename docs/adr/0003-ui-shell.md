# ADR 0003: UI shell (rubric)

Status: **accepted: Tauri 2** (Hoan, 26/11/2026). The Windows spike below still runs early in P2, as a check on the memory numbers; if a 4 GB office PC struggles with the window, Slint is the fallback.

## The split that matters more than the toolkit

Genra runs as two processes:

- **Guard** (`genra-guard`): Rust, no UI. Watches folders, scans, repairs, applies rule packs.
  Always on, so it carries the "light on the machine" budget alone (target ~5–15 MB RAM, ~0% CPU idle).
- **App window**: opened when the user clicks the tray icon or a notification, closed (not hidden)
  afterwards. It talks to the guard over local IPC.

With this split the toolkit's memory only counts while the window is open, which is what makes a
web-view UI acceptable. Every option below is scored assuming the split.

## Rubric

Scores 1–5, weights sum to 100. Numbers are typical published figures for a small app, to be
re-measured on a Windows 11 VM in the spike before this ADR is accepted.

| Criterion (weight) | Tauri 2 | Slint | Native per OS (WinUI 3 + SwiftUI + GTK) | Flutter + Rust |
|---|---|---|---|---|
| Window RAM while open (10) | 3 (WebView2 ≈ 80–150 MB) | 5 (≈ 15–40 MB) | 4 (≈ 40–80 MB) | 3 (≈ 70–130 MB) |
| Installer size (5) | 5 (≈ 3–10 MB, WebView2 ships with Win 10/11) | 5 (≈ 5–15 MB) | 3 (Windows App SDK runtime) | 4 (≈ 20–40 MB) |
| Window open time (5) | 4 (≈ 0.5–1 s) | 5 (< 0.3 s) | 4 | 4 |
| Modern native look (15) | 3 (Fluent via CSS, Mica via plugin) | 3 (Fluent / Cupertino styles, less polish) | 5 | 2 (custom look) |
| Accessibility: screen reader, text size (10) | 4 (browser a11y tree) | 3 (AccessKit, maturing) | 5 | 3 |
| One codebase for Win/mac/Linux (15) | 5 | 5 | 1 (three UIs) | 5 |
| Reuse for the web file check, Q3 (5) | 5 (same UI in the browser) | 2 (WASM canvas, different feel) | 1 | 3 (Flutter web, heavy) |
| Speed of building for one maintainer (15) | 5 | 4 | 2 | 4 |
| Contributor pool (10) | 5 (web developers) | 2 | 3 | 4 |
| Rust core integration (5) | 5 (same process / commands) | 5 (pure Rust) | 3 (UniFFI; C# via community binding) | 4 (flutter_rust_bridge) |
| Maturity / long-term risk (5) | 4 | 3 (smaller company; licence: royalty-free with attribution, or GPL) | 4 | 4 |
| **Weighted total (of 100)** | **86** | **76** | **63** | **72** |

Electron is left out: ≈ 150–300 MB RAM and ≈ 80–150 MB installer break principle 9.

## Reading the scores

- **Tauri 2 wins** on one codebase, web reuse, build speed and contributors. Its weak spot, memory,
  only applies while the window is open because of the guard/window split.
- **Slint is the light-weight runner-up.** Pick it instead if the spike shows the WebView2 window
  feels heavy on old office PCs (4 GB RAM, HDD), which is plausible for wards.
- **Per-OS native** gives the best look but triples UI work; not right for one maintainer.

## Spike before accepting (1–2 days)

On a Windows 11 VM with 4 GB RAM, build the Home screen in Tauri 2 and in Slint, and measure:
installer size, cold window open time, RAM with the window open, guard RAM idle, and how it reads
with Narrator. Record the numbers here and pick.
