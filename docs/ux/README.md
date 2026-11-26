# Genra AV: UX direction and open questions

Rule for this repo: **UX is locked before UI code.** Each question below gets an answer from Hoan;
the answer is written next to it with the date, then the mock-up is drawn, then code.

## Who and what (draft, confirmed by Q1–Q3)

The first person is someone who uses a computer for work but is not "good with computers": a ward
or commune officer, a shop owner, a parent. Threats reach them as **files** (Zalo, email, USB), not
as websites. What they need is a plain answer to "is this file safe?", and one button that fixes it.

## The core experience: "Dọn giúp tôi", and nothing breaks (Hoan, 26/11)

The product's centre is not the scan, it is the **repair**: Genra steps in for the user, cleans the
machine and the files, and leaves everything working. The user presses one button; Genra does the rest.
Rules for every repair:

1. **Show the plan first, in plain words.** "Gỡ sâu khỏi Excel · làm sạch 3 tệp · không đụng gì khác".
   One button "Dọn sạch giúp tôi"; the list of steps is behind "Xem chi tiết".
   **Clean the machine, not just the file** (Hoan, 26/11): when a threat is found, the default action
   cleans the file *and* removes the worm from the machine and the other infected files, because the
   people we serve cannot be expected to do the second half themselves. "Chỉ làm sạch tệp này" stays
   as a secondary link. On the web check (which cannot touch the machine) the same button becomes
   "Tải Genra để dọn máy".
2. **Only known, reversible actions.** Repairs come from a fixed list in the code (remove a worm
   workbook from XLSTART, write a macro-free copy, move a file aside, reset an Office macro setting).
   Rule packs can *choose* among these actions but never add new kinds. No registry edits, drivers,
   system files or deleting user data outside that list.
3. **Journal and undo.** Every change is written to a journal before it is made; originals are kept
   (quarantine, 30 days). "Hoàn tác" restores the whole repair in one press.
4. **Never leave the machine half-done.** Each step checks its precondition (Excel closed, file not
   in use) and stops cleanly if it cannot finish; the journal rolls back what was done.
5. **Verify after.** Re-scan what was repaired and open-check the clean copy (it parses, row and sheet
   counts match the original); report "Đã dọn xong, máy hoạt động bình thường" only when that passes.
6. **Ask before closing the user's work.** If Excel must be closed, say so and wait; never kill it with unsaved changes.
7. **Works offline,** no account, no upload.

This puts a desktop repair engine early: the web check (Q3) finds problems, the Windows app fixes them.

## Principles

0. **Fewer steps, same result** (Hoan, 26/11): every journey is counted in
   [usability-audit.md](usability-audit.md); everyday journeys take ≤ 2 actions and ≤ 1 moment of attention.
1. **One status, in plain words.** "Máy an toàn" / "Có 1 việc cần xử lý". No jargon on the main
   screen ("macro", "heuristic", "quarantine" only behind "Xem chi tiết").
2. **One primary action per screen.** The button says what happens: "Làm sạch tệp", not "OK".
3. **Every finding answers three things:** what it is, what it does to me, what happens if I press the button.
4. **Nothing is lost.** Every repair can be undone for 30 days; files are moved aside, never deleted.
5. **Quiet by default.** Notify only when the user has something to do; no "you are protected" pop-ups.
6. **Next to Defender, not against it.** Show Defender's state as one health line; never turn it off.
7. **Native and modern on each OS.** Fluent (Windows 11) and standard macOS look; **light theme by default**, dark as an option; respects
   text size and screen readers. No custom chrome.
8. **Vietnamese first,** written for reading aloud: short sentences, everyday words, no English
   unless it is what the user sees on screen elsewhere (Excel, Zalo).
9. **Light on the machine.** Idle: ~0% CPU, under 50 MB RAM, no full-disk scan on a timer, no kernel driver, installer under 15 MB. Battery-friendly on laptops. Numbers are checked in CI on every release.
10. **Colour has meaning.** Graphite surfaces with one blue accent, in the manner of the top AV brands (Hoan, 26/11: no loud gradients; yellow/red would blur with warning/danger). Tokens: [docs/design/tokens.md](../design/tokens.md); silver mark; green = safe, amber = needs a look, red only for malware.

## Screens to mock up first (P1)

Mock-ups v1 (26/11): [light, the default](mocks/v1/overview-light.png) and
[dark](mocks/v1/overview-dark.png); one PNG + SVG per screen in `mocks/v1/light|dark/`, regenerated
by `python3 mocks/v1/generate.py mocks/v1 light|dark`. Screens 1 → 3 → 5 → 4 follow one story: an infected
Excel file arrives, is quarantined, the user presses "Dọn sạch giúp tôi", Genra waits for Excel to be
closed, and reports machine and files clean.

1. **Home**: status card, "Kiểm tra tệp" (drop zone / pick a file), last update time of the rules.
2. **Result: clean**: "Tệp này an toàn" with what was checked, one line.
3. **Result: threat**: name in plain words ("Sâu lây qua Excel"), what it does (3 bullets), the
   list of what Genra will do, one primary button **"Dọn sạch giúp tôi"** (file + machine), secondary
   "Xem chi tiết"; "Chỉ làm sạch tệp này" and "báo nhầm" as small links.
4. **All clean**: "Đã dọn sạch máy và tệp", what was done (worm removed, files cleaned, verified),
   where the clean copies are, what to do next (send them back), "Hoàn tác".
5. **Machine repair** (desktop): found the worm in Excel startup, "Gỡ khỏi máy", undo for 30 days.
6. **Health**: Defender on/updated, Office macro setting, rules up to date.

## Questions (all answered 26/11/2026; A was the proposal)

**Q1. Who is the first user?**
> **Answer (Hoan, 26/11):** everyone, but designed to be easiest for ward/commune officers, the weakest office-IT users. Modern, yet light on the machine (not heavy like the big vendors).
- A. Office workers at wards/communes and small offices (Windows + Office, files via Zalo). Clear need, real samples already.
- B. Families. Bigger market, threats are more phone/web scams than files.
- C. Small businesses / accountants. Pay later, more Excel macros of their own (more false positives).
- D. Everyone at once. No focus, no clear first screen.

**Q2. What is it, next to Windows Defender?**
> **Answer (Hoan, 26/11):** A first (companion to Defender); B (full replacement) stays as the long-term goal for P4.
- A. A companion: checks files and fixes Office worms, shows Defender's health. Small, honest scope.
- B. A full replacement antivirus. Needs real-time driver and Microsoft programmes (P4), years away.
- C. A file checker only (no machine repair). Simplest, but the infected PC keeps infecting.
- D. A web service. No install, but cannot clean XLSTART on the PC.

**Q3. First surface people touch?**
> **Answer (Hoan, 26/11):** cross-platform from the start; Windows is the platform tested first.
- A. Web page with the WASM core (file never leaves the device), then Windows app for repair. Zero install first.
- B. Windows app first. Can repair at once, but install is the hardest step for this audience.
- C. Zalo Mini App. Lives where files arrive, but Zalo platform limits and review.
- D. Browser extension. Catches downloads, but officers rarely install extensions.

**Q4. Native UI technology?** (core stays Rust in every option)
> **Answer (Hoan, 26/11):** Tauri 2, chosen from the rubric in [ADR 0003](../adr/0003-ui-shell.md) (Tauri 86, Slint 76, Flutter 72, per-OS native 63).
- A. Per-OS native: WinUI 3 (C#) on Windows, SwiftUI on macOS, Rust core via UniFFI bindings. Truly native look and accessibility; two UI codebases.
- B. Tauri 2 with a Fluent-styled web UI. One UI codebase, also reused for the web page; looks "almost native".
- C. Slint (Rust-native declarative UI). One codebase, small binary; native styles exist but less polished than A.
- D. Flutter + flutter_rust_bridge. One codebase incl. mobile; not native-looking on desktop.

**Q5. When a malware file is found, by default…**
> **Answer (Hoan, 26/11):** A, move aside (reversible) and tell the user, offering "Làm sạch tệp".
- A. Move it aside (reversible) and tell the user, with "Làm sạch tệp" offered. Safe even if the user does nothing.
- B. Ask every time before doing anything. User stays in control; many will press the wrong button.
- C. Only warn. Least surprise, least protection.
- D. Delete. Final, risky with false positives.

**Q6. Protection while the user works?**
> **Answer (Hoan, 26/11):** A, watch the folders files arrive in; no driver.
- A. Watch Downloads, Zalo received-files folder, XLSTART and USB drives (OS notifications, no driver).
- B. Kernel real-time driver. Full coverage; Microsoft signing, months of work (P4).
- C. Scan only when asked. Simplest; misses the moment a file arrives.
- D. Hook Office via AMSI. Sees macros as they run; Windows-only, needs elevated install.

**Q7. Rule updates?**
> **Answer (Hoan, 26/11):** A, hourly signed pack from a CDN with staged rollout and kill switch.
- A. Hourly check of a signed pack on a CDN, staged rollout 5% → 50% → 100%, kill switch. (ADR 0002)
- B. Push via a long-lived connection. Faster, needs a server always on.
- C. With app updates only. Slow, the problem we want to avoid.
- D. When the user presses "Cập nhật". Many never press it.

**Q8. What leaves the user's machine?**
> **Answer (Hoan, 26/11):** A, nothing by default; opt-in sends only the hash of a detected file.
- A. Nothing by default; opt-in sends the hash of a detected file (never content) to count families.
- B. Nothing ever. Most private; we never learn what spreads.
- C. Ask to submit the suspicious file itself for analysis, per file. Best for new rules; trust burden.
- D. Full telemetry. Easiest for us; wrong for this product.

**Q9. Licence when it opens up?**
> **Answer (Hoan, 26/11):** A, Apache-2.0.
- A. Apache-2.0. Easy for others to use and contribute, including companies.
- B. GPL-3.0. Forks must stay open; some companies stay away.
- C. MPL-2.0. File-level copyleft, middle ground.
- D. Source-available (e.g. BSL). Protects a future business; not "open source" to the community.

**Q10. Languages at launch?**
> **Answer (Hoan, 26/11):** A, Vietnamese + English, strings in files from day one.
- A. Vietnamese + English (strings in files from day one, community can add more).
- B. Vietnamese only. Faster, but closes the door to outside contributors.
- C. English first. Wrong for the first users.
- D. VN + EN + Chinese/Khmer/Lao for the region. Too much before P2.

**Q11. How does a user tell us "this is wrong" (false positive)?**
> **Answer (Hoan, 26/11):** A, a "Tệp này an toàn, báo nhầm" button on the result (hash + note → next pack's allow list).
- A. Button "Tệp này an toàn, báo nhầm" on the result → hash only + their note → next pack's allow list.
- B. Email / form on the website. Fewer reports, more detail.
- C. GitHub issues. Fine for developers, not for officers.
- D. No reporting. False positives stay until someone notices.

**Q12. Mascot or no mascot in the UI?**
> **Answer (Hoan, 26/11):** A + B + C: no mascot in the app; the ☶ mark closes its gate in a short motion when a threat is blocked; a mascot only in tutorials and videos.
- A. No mascot; the ☶ mark is the character (calm, serious, works for offices).
- B. A small animated mark that "closes the gate" when a threat is blocked. Delight, little cost.
- C. A mascot animal for tutorials only.
- D. A mascot everywhere. Friendly, risks looking unserious.
