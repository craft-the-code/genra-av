# Usability audit: fewer steps, same result

**Philosophy (Hoan, 26/11/2026): cut the number of steps and the moments that need the user's
attention, never the effectiveness.** Every journey is counted, and a change that adds a step needs
a reason written here.

How we count:
- **Action**: a deliberate click, key press, drag or choice in a dialog.
- **Attention**: a moment the user must read and decide (a notification, a warning, a question).
- **Wait**: the user must do something outside Genra first (save in Excel, plug in a drive).

Target for every everyday journey: **≤ 2 actions and ≤ 1 attention moment** in the common case.
Anything that needs the user arrives as **one notification that carries its own fix button**.

## Journeys (v1 mock-ups vs. target)

| # | Journey | v1 mock-up / app shell | Target v0.1 | How |
|---|---|---|---|---|
| J1 | Check a file received on Zalo | 5–7 actions: open Genra → Kiểm tra tệp → Chọn tệp → find folder → pick → open → read | **0** when the guard sees it arrive (silent if clean); **1** by hand: right-click → "Kiểm tra bằng Genra AV" | Folder guard on Zalo/Downloads; Explorer/Finder context menu; drop on the app or its tray icon also works |
| J2 | Clean an infected file and the machine | 3–4 actions + 1 wait (save and close Excel yourself) + "Mở thư mục" + rename | **1 action** ("Dọn sạch giúp tôi"); if Excel is open: **1 more** ("Đóng Excel giúp tôi", Excel itself asks to save) | The clean copy **replaces the file in place** (original kept in quarantine), so there is nothing to find or rename; Genra asks Excel to close politely instead of telling the user to do it |
| J3 | Quick scan of the machine | 2 (Tổng quan → Quét nhanh máy) | **1** on Tổng quan; **0** after install (first quick scan runs once on its own) | Status card always holds the single most important action |
| J4 | Undo a repair | 3 (Đã cách ly → item → Khôi phục) | **1** ("Hoàn tác" on the done screen and in the notification), 3 later from history | Undo travels with the result |
| J5 | Report a false positive | 3 (link → note → Gửi) | **1** (note optional, sent with one press) | The note field is optional and prefilled with nothing |
| J6 | Fix a health issue (Office runs every macro) | 2 (Sức khoẻ máy → Sửa giúp tôi) | **1** when it is the top issue (shown on the status card) | Same rule as J3 |
| J7 | First run | install wizard + app + opt-in question | **1 installer screen + 1 first-run screen** with safe defaults (hash reports off) | No account, no tour; the first quick scan starts by itself |
| J8 | USB stick plugged in | not designed | **0** if clean; **1 attention** + 1 action if not | Scan on mount, notification with "Dọn sạch" |

## Navigation

Six sidebar items is more than the user needs to think about. Proposal for v0.1:

| Now | Proposed |
|---|---|
| Tổng quan, Kiểm tra tệp, Dọn máy, Sức khoẻ máy, Đã cách ly, Cài đặt | **Tổng quan**, **Kiểm tra tệp**, **Máy của bạn** (dọn máy + sức khoẻ + khởi động cùng Windows), **Cài đặt**; quarantine becomes "Lịch sử & hoàn tác" inside Tổng quan |

Fewer places to look, same reach: every repair and every undo is still one press away from where
the problem was shown.

## Rules that follow

1. **One primary action per screen**, and it is the one that solves the problem end to end.
2. **Do it for the user when it is safe and reversible**; ask only when it touches their open work.
3. **Never send the user to another app or folder to finish a job** Genra can finish itself.
4. **Results travel with their fix and their undo** (screen, notification, tray menu).
5. **Silence is a feature**: clean results do not notify; the status card shows "Máy an toàn" and nothing else.
6. Every new screen or setting lists its step count in its PR; the table above is updated.

## Checks before v0.1

- Count steps on a fresh Windows 11 VM for J1–J8 with a stopwatch; record actions/attention/time here.
- Five-person hallway test with office workers who are not "good with computers": can they clean the
  Kangatang sample with no help? Target: 5/5, under 60 seconds, no question asked.
