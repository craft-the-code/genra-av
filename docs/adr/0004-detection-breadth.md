# ADR 0004: catch common malware, not only Office macros

Status: **accepted** 27/11/2026 (Hoan chose option B over hash-only (A) and bundling ClamAV (C); the comparison page lives outside the repo).

## Context

Genra AV is strong on one thing (with #20): Office documents with VBA or Excel 4.0 macros, remote templates,
and cleaning them without losing data. Anything else (a stealer `.exe` in Downloads, a `.js` dropper
inside a `.zip` from Zalo, a `.lnk` on a USB stick that starts PowerShell) is only caught when its
exact SHA-256 is on the MalwareBazaar list, and even then it is "suspicious", never moved aside
(public hash feeds are untrusted by design, ADR 0002).

Hoan, 27/11: Genra must not be "too simple"; it should quarantine the common malware people actually
get, at 80–90 % of what Kaspersky or Bitdefender catch (strategy.md), while staying light and never
breaking the machine.

What the big suites do that we can do too, without their cloud or their kernel drivers:

1. Large, graded hash reputation (millions of hashes, updated hourly).
2. Signature rules for families (YARA-like), so new builds of a known family are caught without their hash.
3. Static heuristics for the delivery formats: scripts, shortcuts, archives, double extensions.
4. A second engine: on Windows, Microsoft Defender is already there and good on executables.
5. Behaviour monitoring (kernel/ETW): out of scope for now (heavy, risky, needs a signed driver).

## Decision

Four layers, each shipped as data in the signed pack where possible, each measured before it can
quarantine anything.

### 1. Graded hash reputation

- Keep MalwareBazaar, and add abuse.ch's other payload feeds (URLhaus payloads, ThreatFox SHA-256
  IOCs). All are free with the key we already have.
- **Grade instead of trusting a feed as a whole.** The family name on a MalwareBazaar entry is set by
  whoever submitted it, so it is not enough on its own: one mislabelled popular clean file would be
  quarantined on every PC. A hash is `trusted` (may quarantine) only when **all** of these hold:
  - its entry names a family on a curated list of commodity families (AgentTesla, Formbook, Remcos,
    AsyncRAT, RedLine, Lumma, Emotet, QakBot, njRAT, …, kept in `rules/families.json`);
  - independent engines agree: MalwareBazaar's vendor results show detections by at least 3 engines;
  - it has been listed for at least 48 hours without being removed or reported as a false positive.
  Everything else stays `suspicious`. The CI writes two lists: `trusted-<v>.bin` and `feeds-<v>.bin`,
  and the signing job recomputes the trusted list from the same inputs with the code on `main`
  instead of taking the build job's word for it. On the client, the safety rails below still apply:
  a file signed by Microsoft or an allow-listed publisher is never quarantined on hash evidence alone.
- **Size**: the pack carries the last 90 days (tens of thousands of hashes, about 1–3 MB). Older
  hashes go to an online lookup (below) instead of every PC.
- **Online lookup by hash prefix**: the app sends only the first 5 hex characters (20 bits) of a
  file's SHA-256 to `genra-api` and gets back every known-bad hash with that prefix (the k-anonymity
  model "Have I Been Pwned" uses); the match is made on the PC. What leaks, stated plainly: the
  prefix narrows the file to one of about a million buckets, and the request carries the PC's IP
  address. The server keeps no request log with IP addresses or prefixes beyond rate limiting.
  On by default (decided below).

### 2. YARA-X rules for families

- Engine: [YARA-X](https://github.com/VirusTotal/yara-x) (Rust, BSD-3-Clause): same language as the
  YARA rules the industry shares, safe to embed, no C dependency.
- Rules: open sets with licences we may redistribute (ReversingLabs YARA rules, MIT; rules from YARA
  Forge whose own licence is permissive). The CI checks every rule's licence metadata and drops the
  rest. Rules travel in the signed pack as source and compile on the client.
- Each rule carries a severity. Only rules with a measured false-positive rate of zero on the clean
  corpus (layer 5) may be `malware`; the rest are `suspicious`.

### 3. Heuristics for how malware arrives (built in, no pack needed)

- Archives: look inside `.zip` (and `.7z`/`.rar` later) from Downloads, Zalo and USB, with the same
  zip-bomb budget the Office reader has.
- Scripts and shortcuts: `.js/.jse/.vbs/.vbe/.wsf/.hta/.ps1/.bat/.cmd` with download-and-run
  patterns or heavy obfuscation; `.lnk` whose target is a script host (powershell, mshta, wscript,
  cmd) with arguments; `.url` pointing at a script or UNC path.
- Disguise: double extensions (`baocao.pdf.exe`), right-to-left override characters in names,
  executables with Office/PDF icons named like documents.
- USB worm pattern: shortcuts named like the drive's folders while the real folders are hidden.

### 4. Microsoft Defender as a second opinion (Windows)

- For executables and scripts that layers 1–3 call suspicious, ask Defender: `MpCmdRun.exe -Scan
  -ScanType 3 -File <path> -DisableRemediation`. A Defender detection upgrades the finding to
  `malware`; Defender's own name for it is shown.
- Only when Defender is on (health check already reads that). Genra sends nothing itself, but
  Defender follows its own settings: with "automatic sample submission" on (the Windows default),
  Defender may upload a suspicious file to Microsoft. The privacy policy says so.

### What quarantines, what asks

| Evidence | Verdict | Action |
|---|---|---|
| Pack rule (Kangatang…), YARA rule rated malware, trusted hash, Defender agrees | Malware | Moved aside automatically, one notification with "Hoàn tác" |
| Untrusted hash, heuristic, YARA rule rated suspicious | Suspicious | One press: "Cách ly" (default button) or "Bỏ qua" |
| Office file with macros | (unchanged) | "Dọn sạch giúp tôi" keeps the data |

Safety rails, whatever the evidence: never quarantine a file signed by Microsoft or a publisher on
the pack's allow list on hash or heuristic evidence alone; never delete (quarantine is reversible for
30 days); every quarantine is undoable from history; the pack's `disabled`/`allow_sha256` brakes work
for every layer.

### 4b. Disinfection: one "Dọn sạch giúp tôi" for every kind of threat

Hoan, 27/11: most users in Vietnam are weak at office IT; quarantining a file is half the job, the
other half is giving them their machine and USB stick back. Knowing the family (layers 1 and 3) is
what tells Genra what that family leaves behind.

| Left behind | Genra does | Today |
|---|---|---|
| Macros in Excel/Word files | Clean copy replaces the file, data kept | done |
| Copy in Excel's startup folder | Remove from XLSTART, macro blocking back on | done |
| USB: real folders hidden, fake shortcuts in their place | Delete the fake shortcuts, unhide the real folders and files | new (step 2) |
| Starts with Windows | Remove Run/RunOnce, Startup folder, scheduled tasks that point at a quarantined file | partly (startup list) |
| Running process | Stop the quarantined file's process; if it resists, finish at next start | new |
| Settings changed | Remove Defender exclusions the malware added, restore "show hidden files", Office macro policy | Office only |

Same rules as the Office repair: every change in the journal and undoable, never touch anything not
traced to the threat, scan again at the end.

### 5. Measurement gates every layer

- **Malware corpus**: samples pulled from MalwareBazaar in CI (zipped, never executed), by type
  (exe, dll, js, vbs, lnk, office, archive). Metric: detection rate per type and per layer.
- **Clean corpus**: Windows system files, common installers, a few thousand Office files from public
  sources. Metric: false positives. **Target: 0 malware-level false positives; under 0.1 % suspicious.**
- The CI publishes a detection report per release (strategy.md, "How we measure"). A layer cannot rate
  anything `malware` until its numbers are in that report.

## Learn from the open-source engines, without their weight

ClamAV, YARA, capa and Loki carry decades of detection practice. Take the ideas, not the footprint:

| From | Take | Leave |
|---|---|---|
| ClamAV | Section and import hashes for PE files (a family rebuilt with new resources keeps its code sections); unpacking archives with budgets; signature categories (PUA vs malware); incremental database updates | The 300 MB database loaded in RAM, the GPL engine in-process, scanning every file type on disk |
| YARA / YARA-X | The rule language everyone shares, run by the embeddable YARA-X engine | Rule sets we may not redistribute, slow rules (the CI rejects rules over a time budget on the corpus) |
| capa | Describing what a program can do (downloads, persists, injects) to explain a finding in plain words | Its full disassembly at scan time |
| Loki / THOR Lite | Filename and path indicators for the places malware drops itself | Scanning the whole disk by default |

Lean by construction: only file types that can carry code are read, the scan cache skips unchanged
files, rules compile once per pack, and the pack stays a few MB.

## For people who are not good with computers

Every layer ends in the same few interactions (usability-audit.md): nothing when clean; malware is moved
aside with one notification that carries "Hoàn tác"; a suspicious file asks once with "Cách ly" as the
main button; "Dọn sạch giúp tôi" fixes what the threat left behind. Messages name what the user sees
("USB của bạn có lại các thư mục bị ẩn"), never the technique.

## Order

1. Graded hashes, families list and the measurement harness (gives numbers for everything after).
2. Archive scanning and script/shortcut/disguise heuristics (where Vietnamese users get hit), with
   USB disinfection (unhide the real folders), then disinfection on the machine (4b).
3. YARA-X engine and licensed rule sets.
4. Defender second opinion.
5. Online k-anonymity lookup (after the privacy decision).

Each step is its own PR with the detection report before and after.

## Consequences

- Genra gains real coverage on executables and scripts without a cloud dependency or a driver.
- The pack grows (rules and two hash lists); kept under ~5 MB by the 90-day window.
- More layers mean more false-positive risk; the measurement gate and the safety rails are the
  answer, not caution in the rules themselves.
- Behaviour monitoring stays out; a future ADR covers it if the numbers show the static layers plateau.

## Decided with Hoan (27/11)

1. **Online lookup**: on by default, described in the privacy policy, can be turned off in Settings.
   The policy changes from "sends nothing" to what is true: "never sends your files; to check a file
   it sends the first 5 characters of its fingerprint, shared by about one file in a million".
   Ships last (step 5), with the policy change in the same release.
2. **Suspicious items**: ask once, "Cách ly" is the main button. Malware is quarantined without asking.
3. **Defender second opinion**: yes, only when Defender is on; the privacy policy mentions Defender's
   own sample submission.
