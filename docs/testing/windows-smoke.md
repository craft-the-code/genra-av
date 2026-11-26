# Windows smoke test (before promoting a pre-release)

Run on a real Windows 10/11 PC with Microsoft Excel installed. Takes about 20 minutes. Tick each
line; any ✗ blocks promotion. Report problems with the in-app "Báo lỗi" button or a GitHub issue.

Test files: use a **copy** of a known infected sample (Kangatang .xls) kept in an encrypted zip
(password `infected`), and one clean .docx/.xlsx you made yourself. Never open the infected copy in Excel.

## 1. Install

- [ ] Download `Genra-AV-Setup.exe` from the release page (tag link, `releases/download/vX.Y.Z/…`).
- [ ] `certutil -hashfile Genra-AV-Setup.exe SHA256` matches the line in `SHA256SUMS`.
- [ ] Windows SmartScreen shows "unrecognised app" (expected while unsigned): More info → Run anyway.
- [ ] Installs per user without an admin prompt; Start menu entry "Genra AV" exists; app opens in < 3 s.
- [ ] Settings shows the rule pack version (not "đi kèm ứng dụng" after ~1 minute online) and the install id.

## 2. Check a file

- [ ] Drag the clean .docx onto the window → "Tệp này an toàn".
- [ ] Drag the infected copy → "Tệp này có sâu lây qua Excel" with the three bullets.
- [ ] "Xem chi tiết" shows rule ids, VBA module names and SHA-256.
- [ ] Switch language to English in Settings → the threat text is English.

## 3. Clean the file and the machine

- [ ] Put a second copy of the infected file in `%APPDATA%\Microsoft\Excel\XLSTART\mypersonnel.xls`
      and a third in Documents.
- [ ] Open Excel with an empty, **unsaved** workbook (type something in A1).
- [ ] Press "Dọn sạch giúp tôi" → the "Cần đóng Excel" screen appears and lists the open workbook.
- [ ] Press "Đóng Excel giúp tôi" → Excel asks to save (choose Don't save) and closes; Genra continues by itself.
- [ ] Done screen lists: worm removed from XLSTART, files cleaned (3), checked again.
- [ ] The cleaned file opens in Excel with the same data (rows, columns, formatting) and no macro warning.
- [ ] `XLSTART\mypersonnel.xls` is gone.
- [ ] Press "Hoàn tác" → all three originals are back (same SHA-256 as before), XLSTART file back.
      Then delete them again by hand.

## 4. Máy của bạn

- [ ] Health shows Windows Defender on/updated, Windows Update date, firewall, Office macro setting.
- [ ] Set Excel's macro setting to "Enable all macros" (Trust Center) → reopen Genra → Warn with
      "Sửa giúp tôi" → press it → Excel's setting is back to "Disable with notification" → Hoàn tác restores it.
- [ ] Startup list shows Run keys and Startup folder items with publisher/signature; nothing system-scoped can be disabled.

## 5. Quick scan and USB

- [ ] "Quét nhanh máy" finishes, shows progress, and a second run is much faster.
- [ ] Plug in a USB stick with a copy of the infected file → it is found by the quick scan
      (removable drive listed as a target).
- [ ] A copy of the infected file in `Pictures` (and, if OneDrive moves Documents, in
      `OneDrive\Documents`) is found by the quick scan.
- [ ] "Quét toàn bộ máy" walks C: and D: (if present), shows "Dừng"; pressing it ends the scan with
      "Đã dừng quét giữa chừng", never "Máy an toàn", and earlier findings stay listed.
- [ ] "Chọn thư mục để quét…" opens the folder picker; a folder holding a copy of the infected file
      lists it under "Tệp tìm thấy".

## 6. Update and uninstall

- [ ] Updates reach official releases only (GitHub's `releases/latest` skips pre-releases). After
      promoting this version, a PC still on the previous official version offers the update and installs it.
- [ ] Uninstall from Settings → Apps; `%LOCALAPPDATA%\Genra AV` keeps quarantine/journal only if the user chose to.

Record: Windows version, Excel version, result per section, and the install id used.
