# Genra AV: the big picture

Goal (Hoan, 26/11/2026): a full antivirus, not an Office-macro cleaner. Detection **80–90% of what
Kaspersky or Bitdefender catch** is the target for an open-source product, with a lighter footprint
and a much simpler experience. This file is how we get there and how we know when we have.

## What the leaders actually do (layers)

A modern antivirus is a stack of independent detectors; each catches what the others miss. Genra
builds the same stack in order of value per effort.

| # | Layer | What it catches | Genra plan |
|---|---|---|---|
| 1 | **Hash reputation** | Known samples, exact copies | Public feeds (e.g. abuse.ch MalwareBazaar) folded into signed packs; opt-in cloud lookup against our backend later |
| 2 | **Content rules** | Families with stable code or strings | Today: our JSON rules on VBA. Next: **YARA-X** rules (ours + community sets, each set's licence checked before shipping) |
| 3 | **Format-aware parsers** | Threats hidden inside containers | Today: OLE2/OOXML + VBA. Next: archives (zip/rar/7z), PDF (JS, launch actions), LNK, HTA/scripts (JS, VBS, PowerShell), ISO/IMG, Windows PE |
| 4 | **Static ML on executables** | *Unknown* Windows malware: the bulk of the gap to the leaders | Gradient-boosted model on PE features, trained on the open EMBER datasets, shipped as a small ONNX file inside the pack (updates without an app release) |
| 5 | **Behaviour** | Malware that only shows itself when it runs: ransomware, droppers, persistence | Watch process starts, script engines and persistence points (Run keys, Startup, scheduled tasks, services, XLSTART); ransomware canaries and mass-rename detection; kill and roll back |
| 6 | **Repair** | What is already on the machine | Our "Dọn sạch giúp tôi" engine: fixed list of reversible actions, journal, undo, verify (docs/ux) |
| 7 | **Web** | Phishing and malicious downloads | DNS/URL blocklists (e.g. URLhaus) applied by the app; browser integration later |

Real-time protection per OS: Windows needs a file-system minifilter driver (Microsoft-signed, P4) for
true on-access blocking; until then the guard reacts to file events in the folders threats arrive in.
macOS uses the Endpoint Security framework (needs an Apple entitlement); Linux uses fanotify.

## How we stay light

- Scan on events, not on a timer; cache verdicts by hash + size + modified time; never rescan unchanged files.
- Cheap checks first (hash, file type, rules), the ML model only for executables, behaviour only on
  the few processes that touch persistence or many files.
- The guard runs at low priority with a memory budget (principle 9 in docs/ux); the UI only when opened.
- One signed pack carries hashes, rules and the ML model, so detection improves weekly without an app update.

## How we measure (no claim without numbers)

- `bench/` harness (P2): a **malware set** of recent samples (by hash, downloaded into a sandbox, never
  into Git) and a **clean set** of common Windows/Office software and real office documents.
- Report per pack: detection rate per layer and in total, false-positive rate, scan time per GB, idle RAM/CPU.
- Targets for the first public "full AV" release: ≥ 80% detection on samples from the last 30 days,
  ≤ 0.1% false positives on the clean set. Independent lab tests (AV-Comparatives, AV-TEST) once we
  are close; until then the README says plainly that Genra is a companion to Windows Defender.

## Open source: trade-offs and how we handle them

| Concern | Answer |
|---|---|
| Attackers read the detection logic and evade it | They reverse closed engines too. The engine is open; **detections are data in signed packs**. Fresh rules for active campaigns can be built in a private rules repo and published only inside packs, then opened later. |
| Fake "Genra" builds carrying malware | Download only from GitHub Releases; signed installers; checksums and build attestations; Apache-2.0 grants no trademark rights to the name or logo (§6). |
| Users must trust what we collect | The backend is public in this repo: anyone can read exactly what is stored. This is a reason to be open, not a risk. |
| Maintenance load | Issue templates, a clear SECURITY.md, and rule contributions through pull requests with tests. |

## Admin and insights

The admin is a separate set of routes (`/admin/*`) on the same Worker, behind **Cloudflare Access**
(free for small teams): the Worker also verifies the Access JWT, so the code can be public while the
data stays private. First screens: reports by kind and rule, false positives per rule (feeds the
allow list), samples to triage, installs per version and OS (counts only).
