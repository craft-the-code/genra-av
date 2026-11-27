#!/usr/bin/env python3
"""Draws the pictures of docs/install/windows.*.md: the warnings Windows and Edge show for an
unsigned installer, and Genra's installer pages, in Vietnamese and English.

They are drawings, not screenshots: no Windows machine is needed, and no picture from elsewhere
is reused. Wording comes from the products' own language files where it could be checked
(SmartScreen and Edge button names, NSIS and Tauri's Vietnamese installer strings); the rest
follows them closely. The guide calls them illustrations.

  python3 docs/install/generate.py            # writes docs/install/img/*.png
Needs Google Chrome (headless) for the PNGs. Standard library only.
"""
import html
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "img")
FILE = "Genra-AV-Setup.exe"
RING = "#F5A524"

T = {
    "vi": {
        "edge_title": "Tệp tải xuống",
        "edge_warn": f"<b>{FILE}</b> không được tải xuống phổ biến. Hãy đảm bảo bạn tin tưởng {FILE} trước khi mở.",
        "delete": "Xóa",
        "keep": "Giữ",
        "dlg_title": f"Hãy đảm bảo bạn tin tưởng {FILE} trước khi mở",
        "dlg_text": "Microsoft Defender SmartScreen không xác minh được tệp này vì ít người tải xuống.",
        "show_more": "Hiện thêm",
        "keep_anyway": "Vẫn giữ",
        "report": "Báo cáo tệp này là an toàn",
        "cancel": "Hủy",
        "ss_title": "Windows đã bảo vệ PC của bạn",
        "ss_text": "Microsoft Defender SmartScreen đã ngăn một ứng dụng không xác định khởi động. Việc chạy ứng dụng này có thể khiến PC của bạn gặp rủi ro.",
        "more_info": "Thông tin thêm",
        "app": "Ứng dụng:",
        "publisher": "Nhà phát hành:",
        "unknown": "Nhà phát hành không xác định",
        "run_anyway": "Vẫn chạy",
        "dont_run": "Không chạy",
        "setup": "Cài đặt Genra AV",
        "welcome_title": "Chào mừng đến với Trợ lí Cài đặt Genra AV",
        "welcome_text": "Trình trợ lí sẽ hướng dẫn bạn việc cài đặt Genra AV.<br><br>Bạn nên đóng tất cả các chương trình khác trước khi bắt đầu cài đặt.<br><br>Nhấn Tiến để tiếp tục.",
        "next": "Tiến &gt;",
        "back": "&lt; Lùi",
        "install": "Cài đặt",
        "cancel_nsis": "Hủy bỏ",
        "dir_title": "Chọn thư mục cài đặt",
        "dir_sub": "Chọn thư mục để cài đặt Genra AV.",
        "dir_text": "Genra AV sẽ được cài vào thư mục dưới đây. Không cần đổi gì: nhấn Cài đặt.",
        "dir_label": "Thư mục cài đặt",
        "browse": "Duyệt...",
        "finish_title": "Hoàn tất Cài đặt Genra AV",
        "finish_text": "Genra AV đã được cài đặt vào máy tính của bạn.<br><br>Nhấn “Hoàn thành” để đóng Trình trợ lí.",
        "run": "Chạy Genra AV",
        "desktop": "Tạo biểu tượng ngoài màn hình",
        "finish": "Hoàn thành",
    },
    "en": {
        "edge_title": "Downloads",
        "edge_warn": f"<b>{FILE}</b> isn't commonly downloaded. Make sure you trust {FILE} before you open it.",
        "delete": "Delete",
        "keep": "Keep",
        "dlg_title": f"Make sure you trust {FILE} before you open it",
        "dlg_text": "Microsoft Defender SmartScreen couldn't verify if this file is safe because it isn't commonly downloaded.",
        "show_more": "Show more",
        "keep_anyway": "Keep anyway",
        "report": "Report this app as safe",
        "cancel": "Cancel",
        "ss_title": "Windows protected your PC",
        "ss_text": "Microsoft Defender SmartScreen prevented an unrecognized app from starting. Running this app might put your PC at risk.",
        "more_info": "More info",
        "app": "App:",
        "publisher": "Publisher:",
        "unknown": "Unknown publisher",
        "run_anyway": "Run anyway",
        "dont_run": "Don't run",
        "setup": "Genra AV Setup",
        "welcome_title": "Welcome to Genra AV Setup",
        "welcome_text": "Setup will guide you through the installation of Genra AV.<br><br>It is recommended that you close all other applications before starting Setup.<br><br>Click Next to continue.",
        "next": "Next &gt;",
        "back": "&lt; Back",
        "install": "Install",
        "cancel_nsis": "Cancel",
        "dir_title": "Choose Install Location",
        "dir_sub": "Choose the folder in which to install Genra AV.",
        "dir_text": "Setup will install Genra AV in the following folder. Nothing to change: click Install.",
        "dir_label": "Destination Folder",
        "browse": "Browse...",
        "finish_title": "Completing Genra AV Setup",
        "finish_text": "Genra AV has been installed on your computer.<br><br>Click Finish to close Setup.",
        "run": "Run Genra AV",
        "desktop": "Create desktop shortcut",
        "finish": "Finish",
    },
}

BASE_CSS = f"""
*{{box-sizing:border-box}}
html,body{{margin:0;background:#E9EDF3;font-family:"Segoe UI","Segoe UI Variable",-apple-system,"Helvetica Neue",Arial,sans-serif;color:#1b1b1b}}
.stage{{padding:28px;display:inline-block}}
.ring{{position:relative;outline:4px solid {RING};outline-offset:5px;border-radius:6px}}
.badge{{position:absolute;top:-22px;right:-22px;width:30px;height:30px;border-radius:50%;background:{RING};color:#1b1b1b;
  font:700 17px/30px "Segoe UI",-apple-system,Arial,sans-serif;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.35)}}
.btn{{display:inline-block;padding:6px 22px;border:1px solid #adadad;background:#e1e1e1;font-size:14px;min-width:88px;text-align:center}}
"""


def ring(inner: str, n: int) -> str:
    return f'<span class="ring" style="display:inline-block">{inner}<span class="badge">{n}</span></span>'


def edge_keep(t):
    return f"""
<div style="width:430px;background:#fff;border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.22);font-size:14px">
  <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 16px;border-bottom:1px solid #eee">
    <b style="font-size:15px">{t['edge_title']}</b><span style="color:#666;letter-spacing:6px">📁 🔍 ··· 📌</span></div>
  <div style="display:flex;gap:12px;padding:14px 16px;align-items:flex-start;position:relative">
    <div style="font-size:26px;line-height:1">⚠️</div>
    <div style="flex:1;line-height:1.45;color:#333">{t['edge_warn']}</div>
    {ring('<div style="padding:2px 8px;font-size:18px;font-weight:700;color:#333">···</div>', 1)}
  </div>
  <div style="margin:0 16px 16px 150px;background:#fff;border:1px solid #ddd;border-radius:8px;box-shadow:0 6px 18px rgba(0,0,0,.18);padding:6px 0;width:230px">
    <div style="padding:8px 16px;color:#333">🗑 {t['delete']}</div>
    <div style="padding:4px 10px">{ring(f'<div style="padding:4px 6px;font-weight:600">✓ {t["keep"]}</div>', 2)}</div>
  </div>
</div>"""


def edge_keep_anyway(t):
    return f"""
<div style="width:520px;background:#fff;border-radius:8px;box-shadow:0 10px 32px rgba(0,0,0,.25);padding:24px 26px;font-size:14px">
  <div style="font-size:19px;font-weight:600;line-height:1.3;margin-bottom:10px">{t['dlg_title']}</div>
  <div style="color:#444;line-height:1.5;margin-bottom:18px">{t['dlg_text']}</div>
  <div style="display:flex;gap:10px;align-items:center;margin-bottom:16px">
    <span class="btn" style="background:#0f6cbd;color:#fff;border-color:#0f6cbd;border-radius:4px">{t['report']}</span>
    <span class="btn" style="border-radius:4px;background:#fff">{t['cancel']}</span></div>
  <div style="margin-bottom:30px">{ring(f'<span style="color:#0f6cbd;padding:2px 4px">{t["show_more"]} ⌄</span>', 1)}</div>
  <div style="padding-left:18px;border-left:2px solid #e3e3e3;margin-left:6px">{ring(f'<span style="color:#0f6cbd;padding:2px 4px;font-weight:600">{t["keep_anyway"]}</span>', 2)}</div>
</div>"""


def smartscreen(t, more: bool):
    detail = ""
    if more:
        detail = f"""<div style="margin-top:22px;font-size:15px;line-height:1.8">
          <div><span style="display:inline-block;width:150px">{t['app']}</span>{FILE}</div>
          <div><span style="display:inline-block;width:150px">{t['publisher']}</span>{t['unknown']}</div></div>"""
        link = ""
        buttons = f"""{ring(f'<span class="btn" style="background:transparent;color:#fff;border:2px solid #fff">{t["run_anyway"]}</span>', 1)}
          <span class="btn" style="background:transparent;color:#fff;border:2px solid #fff;margin-left:14px">{t['dont_run']}</span>"""
    else:
        link = f'<div style="margin-top:16px">{ring(f"<span style=\'text-decoration:underline;padding:2px 4px\'>{t["more_info"]}</span>", 1)}</div>'
        buttons = f'<span class="btn" style="background:transparent;color:#fff;border:2px solid #fff">{t["dont_run"]}</span>'
    return f"""
<div style="width:640px;min-height:400px;background:#1e5aa8;color:#fff;padding:30px 34px 26px;display:flex;flex-direction:column;box-shadow:0 10px 30px rgba(0,0,0,.3)">
  <div style="text-align:right;font-size:18px;opacity:.9">✕</div>
  <div style="font-size:32px;font-weight:300;margin:6px 0 16px">{t['ss_title']}</div>
  <div style="font-size:15px;line-height:1.55;max-width:560px">{t['ss_text']}</div>
  {link}{detail}
  <div style="flex:1"></div>
  <div style="text-align:right;margin-top:30px">{buttons}</div>
</div>"""


def nsis_frame(t, body: str, buttons: str, header: str = "") -> str:
    return f"""
<div style="width:600px;background:#f0f0f0;border:1px solid #7a7a7a;box-shadow:0 10px 30px rgba(0,0,0,.25);font-size:13px">
  <div style="background:#fff;padding:8px 12px;display:flex;justify-content:space-between;border-bottom:1px solid #ddd">
    <span>🛡 {t['setup']}</span><span style="color:#555;letter-spacing:14px">— ✕</span></div>
  {header}
  {body}
  <div style="border-top:1px solid #c8c8c8;padding:12px 14px;display:flex;justify-content:flex-end;gap:10px;align-items:center">{buttons}</div>
</div>"""


SIDEBAR = """<div style="width:164px;min-height:314px;background:linear-gradient(160deg,#0c1a3a,#1d4ed8 70%,#2f6bef);display:flex;align-items:flex-start;justify-content:center;padding-top:34px">
  <div style="color:#fff;font-weight:800;font-size:20px;letter-spacing:2px">GENRA <span style="font-weight:400">AV</span></div></div>"""


def nsis_welcome(t):
    body = f"""<div style="display:flex;background:#fff">{SIDEBAR}
      <div style="padding:22px 22px;flex:1"><div style="font-size:19px;font-weight:700;line-height:1.3;margin-bottom:14px">{t['welcome_title']}</div>
      <div style="line-height:1.5">{t['welcome_text']}</div></div></div>"""
    buttons = f"""<span class="btn" style="color:#999">{t['back']}</span>{ring(f'<span class="btn">{t["next"]}</span>', 1)}<span class="btn" style="margin-left:8px">{t['cancel_nsis']}</span>"""
    return nsis_frame(t, body, buttons)


def nsis_dir(t):
    header = f"""<div style="background:#fff;padding:12px 18px;border-bottom:1px solid #ddd"><b>{t['dir_title']}</b><div style="padding-left:14px;margin-top:3px">{t['dir_sub']}</div></div>"""
    body = f"""<div style="padding:18px 22px;min-height:230px"><div style="line-height:1.5;margin-bottom:22px">{t['dir_text']}</div>
      <fieldset style="border:1px solid #c8c8c8;padding:12px 14px"><legend>{t['dir_label']}</legend>
      <div style="display:flex;gap:10px"><div style="flex:1;background:#fff;border:1px solid #7a7a7a;padding:5px 8px">C:\\Users\\An\\AppData\\Local\\Genra AV</div>
      <span class="btn">{t['browse']}</span></div></fieldset></div>"""
    buttons = f"""<span class="btn">{t['back']}</span>{ring(f'<span class="btn">{t["install"]}</span>', 1)}<span class="btn" style="margin-left:8px">{t['cancel_nsis']}</span>"""
    return nsis_frame(t, body, buttons, header)


def nsis_finish(t):
    body = f"""<div style="display:flex;background:#fff">{SIDEBAR}
      <div style="padding:22px 22px;flex:1"><div style="font-size:19px;font-weight:700;line-height:1.3;margin-bottom:14px">{t['finish_title']}</div>
      <div style="line-height:1.5;margin-bottom:20px">{t['finish_text']}</div>
      <div style="margin-bottom:8px">☑ {t['run']}</div><div>☑ {t['desktop']}</div></div></div>"""
    buttons = f"""<span class="btn" style="color:#999">{t['back']}</span>{ring(f'<span class="btn">{t["finish"]}</span>', 1)}<span class="btn" style="margin-left:8px;color:#999">{t['cancel_nsis']}</span>"""
    return nsis_frame(t, body, buttons)


PICTURES = {
    "1-edge-giu": edge_keep,
    "2-edge-van-giu": edge_keep_anyway,
    "3-smartscreen-thong-tin": lambda t: smartscreen(t, False),
    "4-smartscreen-van-chay": lambda t: smartscreen(t, True),
    "5-cai-dat-tien": nsis_welcome,
    "6-cai-dat-thu-muc": nsis_dir,
    "7-cai-dat-xong": nsis_finish,
}


def chrome() -> str:
    for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", shutil.which("google-chrome") or "", shutil.which("chromium") or ""):
        if c and os.path.exists(c):
            return c
    sys.exit("Google Chrome not found")


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    exe = chrome()
    with tempfile.TemporaryDirectory() as tmp:
        for lang, t in T.items():
            for name, draw in PICTURES.items():
                page = os.path.join(tmp, f"{name}.{lang}.html")
                with open(page, "w", encoding="utf-8") as f:
                    f.write(f'<!doctype html><meta charset="utf-8"><style>{BASE_CSS}</style><div class="stage" id="s">{draw(t)}</div>')
                shot = os.path.join(tmp, "shot.png")
                # Render large, then crop to the stage with the size the browser reports.
                args = [exe, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
                        f"--user-data-dir={os.path.join(tmp, 'profile')}", "--window-size=760,620", f"--screenshot={shot}", "file://" + page]
                for attempt in range(3):
                    if subprocess.run(args, capture_output=True).returncode == 0 and os.path.exists(shot):
                        break
                else:
                    sys.exit(f"Chrome could not draw {name}.{lang}")
                out = os.path.join(OUT, f"{name}.{lang}.png")
                crop(shot, out)
                os.remove(shot)
                print("wrote", os.path.relpath(out, HERE))


def crop(src: str, dst: str) -> None:
    """Trims the page background around the drawing (sips on macOS keeps it standard-library)."""
    import struct
    import zlib

    data = open(src, "rb").read()
    w, h = struct.unpack(">II", data[16:24])
    # Decode the PNG (8-bit RGBA or RGB, as Chrome writes it).
    chunks, pos = [], 8
    bitdepth, ctype = data[24], data[25]
    while pos < len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if typ == b"IDAT":
            chunks.append(data[pos + 8:pos + 8 + ln])
        pos += 12 + ln
    raw = zlib.decompress(b"".join(chunks))
    bpp = 4 if ctype == 6 else 3
    stride = w * bpp
    rows, prev, i = [], bytearray(stride), 0
    for _ in range(h):
        ft = raw[i]
        line = bytearray(raw[i + 1:i + 1 + stride])
        i += 1 + stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            b = prev[x]
            c = prev[x - bpp] if x >= bpp else 0
            if ft == 1:
                line[x] = (line[x] + a) & 255
            elif ft == 2:
                line[x] = (line[x] + b) & 255
            elif ft == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif ft == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(bytes(line))
        prev = line
    bg = rows[0][:3]
    def blank_row(r):
        return all(r[x:x + 3] == bg for x in range(0, stride, bpp))
    top = next(y for y in range(h) if not blank_row(rows[y]))
    bottom = next(y for y in range(h - 1, -1, -1) if not blank_row(rows[y]))
    cols = [any(rows[y][x * bpp:x * bpp + 3] != bg for y in range(top, bottom + 1)) for x in range(w)]
    left = cols.index(True)
    right = w - 1 - cols[::-1].index(True)
    pad = 24
    top, left = max(0, top - pad), max(0, left - pad)
    bottom, right = min(h - 1, bottom + pad), min(w - 1, right + pad)
    out_rows = [b"\x00" + rows[y][left * bpp:(right + 1) * bpp] for y in range(top, bottom + 1)]
    nw, nh = right - left + 1, bottom - top + 1
    def chunk(tag, payload):
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", nw, nh, bitdepth, ctype, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(b"".join(out_rows), 9)) + chunk(b"IEND", b"")
    open(dst, "wb").write(png)


if __name__ == "__main__":
    main()
