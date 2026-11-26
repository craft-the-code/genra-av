# Genra AV: UX direction and open questions

Rule for this repo: **UX is locked before UI code.** Each question below gets an answer from Hoan;
the answer is written next to it with the date, then the mock-up is drawn, then code.

## Who and what (draft, confirmed by Q1–Q3)

The first person is someone who uses a computer for work but is not "good with computers": a ward
or commune officer, a shop owner, a parent. Threats reach them as **files** (Zalo, email, USB), not
as websites. What they need is a plain answer to "is this file safe?", and one button that fixes it.

## Principles

1. **One status, in plain words.** "Máy an toàn" / "Có 1 việc cần xử lý". No jargon on the main
   screen ("macro", "heuristic", "quarantine" only behind "Xem chi tiết").
2. **One primary action per screen.** The button says what happens: "Làm sạch tệp", not "OK".
3. **Every finding answers three things:** what it is, what it does to me, what happens if I press the button.
4. **Nothing is lost.** Every repair can be undone for 30 days; files are moved aside, never deleted.
5. **Quiet by default.** Notify only when the user has something to do; no "you are protected" pop-ups.
6. **Next to Defender, not against it.** Show Defender's state as one health line; never turn it off.
7. **Native and modern on each OS.** Fluent (Windows 11) and standard macOS look; respects light/dark,
   text size and screen readers. No custom chrome.
8. **Vietnamese first,** written for reading aloud: short sentences, everyday words, no English
   unless it is what the user sees on screen elsewhere (Excel, Zalo).
9. **Colour has meaning.** Silver/graphite brand; green = safe, amber = needs a look, red only for malware.

## Screens to mock up first (P1)

1. **Home**: status card, "Kiểm tra tệp" (drop zone / pick a file), last update time of the rules.
2. **Result: clean**: "Tệp này an toàn" with what was checked, one line.
3. **Result: threat**: name in plain words ("Sâu lây qua Excel"), what it does (3 bullets), button
   "Làm sạch tệp" + secondary "Xem chi tiết". Malware result also shows "Máy bạn có thể đã nhiễm".
4. **Clean done**: where the clean copy is, "Mở thư mục", what to do next (send the clean copy back).
5. **Machine repair** (desktop): found the worm in Excel startup, "Gỡ khỏi máy", undo for 30 days.
6. **Health**: Defender on/updated, Office macro setting, rules up to date.

## Questions (answer each; A is the current proposal)

**Q1. Who is the first user?**
- A. Office workers at wards/communes and small offices (Windows + Office, files via Zalo). Clear need, real samples already.
- B. Families. Bigger market, threats are more phone/web scams than files.
- C. Small businesses / accountants. Pay later, more Excel macros of their own (more false positives).
- D. Everyone at once. No focus, no clear first screen.

**Q2. What is it, next to Windows Defender?**
- A. A companion: checks files and fixes Office worms, shows Defender's health. Small, honest scope.
- B. A full replacement antivirus. Needs real-time driver and Microsoft programmes (P4), years away.
- C. A file checker only (no machine repair). Simplest, but the infected PC keeps infecting.
- D. A web service. No install, but cannot clean XLSTART on the PC.

**Q3. First surface people touch?**
- A. Web page with the WASM core (file never leaves the device), then Windows app for repair. Zero install first.
- B. Windows app first. Can repair at once, but install is the hardest step for this audience.
- C. Zalo Mini App. Lives where files arrive, but Zalo platform limits and review.
- D. Browser extension. Catches downloads, but officers rarely install extensions.

**Q4. Native UI technology?** (core stays Rust in every option)
- A. Per-OS native: WinUI 3 (C#) on Windows, SwiftUI on macOS, Rust core via UniFFI bindings. Truly native look and accessibility; two UI codebases.
- B. Tauri 2 with a Fluent-styled web UI. One UI codebase, also reused for the web page; looks "almost native".
- C. Slint (Rust-native declarative UI). One codebase, small binary; native styles exist but less polished than A.
- D. Flutter + flutter_rust_bridge. One codebase incl. mobile; not native-looking on desktop.

**Q5. When a malware file is found, by default…**
- A. Move it aside (reversible) and tell the user, with "Làm sạch tệp" offered. Safe even if the user does nothing.
- B. Ask every time before doing anything. User stays in control; many will press the wrong button.
- C. Only warn. Least surprise, least protection.
- D. Delete. Final, risky with false positives.

**Q6. Protection while the user works?**
- A. Watch Downloads, Zalo received-files folder, XLSTART and USB drives (OS notifications, no driver).
- B. Kernel real-time driver. Full coverage; Microsoft signing, months of work (P4).
- C. Scan only when asked. Simplest; misses the moment a file arrives.
- D. Hook Office via AMSI. Sees macros as they run; Windows-only, needs elevated install.

**Q7. Rule updates?**
- A. Hourly check of a signed pack on a CDN, staged rollout 5% → 50% → 100%, kill switch. (ADR 0002)
- B. Push via a long-lived connection. Faster, needs a server always on.
- C. With app updates only. Slow, the problem we want to avoid.
- D. When the user presses "Cập nhật". Many never press it.

**Q8. What leaves the user's machine?**
- A. Nothing by default; opt-in sends the hash of a detected file (never content) to count families.
- B. Nothing ever. Most private; we never learn what spreads.
- C. Ask to submit the suspicious file itself for analysis, per file. Best for new rules; trust burden.
- D. Full telemetry. Easiest for us; wrong for this product.

**Q9. Licence when it opens up?**
- A. Apache-2.0. Easy for others to use and contribute, including companies.
- B. GPL-3.0. Forks must stay open; some companies stay away.
- C. MPL-2.0. File-level copyleft, middle ground.
- D. Source-available (e.g. BSL). Protects a future business; not "open source" to the community.

**Q10. Languages at launch?**
- A. Vietnamese + English (strings in files from day one, community can add more).
- B. Vietnamese only. Faster, but closes the door to outside contributors.
- C. English first. Wrong for the first users.
- D. VN + EN + Chinese/Khmer/Lao for the region. Too much before P2.

**Q11. How does a user tell us "this is wrong" (false positive)?**
- A. Button "Tệp này an toàn, báo nhầm" on the result → hash only + their note → next pack's allow list.
- B. Email / form on the website. Fewer reports, more detail.
- C. GitHub issues. Fine for developers, not for officers.
- D. No reporting. False positives stay until someone notices.

**Q12. Mascot or no mascot in the UI?**
- A. No mascot; the ☶ mark is the character (calm, serious, works for offices).
- B. A small animated mark that "closes the gate" when a threat is blocked. Delight, little cost.
- C. A mascot animal for tutorials only.
- D. A mascot everywhere. Friendly, risks looking unserious.
