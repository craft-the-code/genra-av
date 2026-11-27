# Roadmap

Where Genra AV stands and what comes next. Dates are when a version shipped; plans have no dates.
Goal (strategy.md): catch 80–90 % of what the big suites catch for the threats Vietnamese offices and
families actually receive, while staying light and asking the user as little as possible.

## Shipped (pre-releases, 26/11/2026)

| Version | What it brought |
|---|---|
| 0.1.0 | Engine (OLE2/OOXML, VBA extraction, signed rule packs, hash lists), "Dọn sạch giúp tôi" with undo (file + XLSTART + Office macro setting), quick scan with cache, quarantine, "Máy của bạn" (health, startup items), app updates, installers for Windows/macOS/Linux |
| 0.1.1 | "Tệp tìm thấy": every file a scan found, one press from its result, kept across restarts |
| 0.1.2 | "Quét tuỳ chọn" (whole computer, or several folders), Stop on every scan, Pictures/Videos/OneDrive in the quick scan |

## 1.0: first official release

The bar for "official": a Windows user can download, install without a scary warning, and clean the
Kangatang worm with no help (usability-audit.md: 5/5 testers, under 60 s, no questions).

- [x] Windows smoke test on a real PC (Hoan, 26/11).
- [x] Loading shown per component, never a blank card or a page-wide wait; one shared busy pattern
      for buttons (`withPending`).
- [x] Scan progress bar, scaled by the last run of the same kind.
- [x] "Máy của bạn" reads health and startup items side by side and starts in the background.
- [ ] **Windows installers signed** through SignPath Foundation (docs/signing.md). Waiting on approval.
- [ ] Landing page download buttons on (`GENRA_RELEASED = true`) once 1.0 is out.
- [ ] Legal pages reviewed by a lawyer (`GENRA_LEGAL_DRAFT` stays true until then).

## Detection and disinfection (ADR 0004, accepted 27/11)

Catch and clean the common malware people get, not only Office macros, while staying light.

- [x] Excel 4.0 macros, remote templates, hidden folders on USB sticks (PR #20).
- [x] 1a. Measurement harness: weekly report, first run 27/11: 570 recent samples, 43 % caught
      (13 % without hash lists), 3 % rated malware; 0 false positives on 21 713 clean files.
- [ ] 1b. Graded hash reputation: trusted families quarantine, re-checked at signing, signed-file rail.
- [ ] 2. Inside archives; scripts, shortcuts, double extensions; USB worm pattern, and USB
      disinfection that unhides the real folders.
- [ ] 2b. Disinfection on the machine: startup entries, running process, Defender exclusions.
- [ ] 3. YARA-X engine with rule sets we may redistribute.
- [ ] 4. Windows Defender as a second opinion on suspicious files.
- [ ] 5. Online lookup by hash prefix (k-anonymity), with the privacy policy change.

## Next (0.2–0.3): reach and fewer steps

- Folder guard: watch Downloads, Zalo and USB sticks live, scan on arrival, notify only when something
  is found (J1, J8 in usability-audit.md). Today "Canh gác" is shown as "sắp có".
- Explorer / Finder context menu "Kiểm tra bằng Genra AV" (J1: one action).
- Hidden folders on USB sticks (worms hide copies there).
- Scanner findings for Excel 4.0 (XLM) macro sheets and remote templates in .docx.
- "Soạn lời nhắn": a ready message to tell the sender their file is infected (mock 5).
- Threat screen shows the computed repair plan before the press.

## Later

- Microsoft Store channel (MSIX, re-signed by the Store).
- Detection measurement against a public corpus (strategy.md, "How we measure"), published per release.
- Wider file types: scripts and shortcuts arriving in archives, PDF with JavaScript.
- Own domain (genraav.com) for the landing page and backend.
