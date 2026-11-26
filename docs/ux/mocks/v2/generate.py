# Mock-up generator v2 (docs/design/brand-system.md, docs/ux/usability-audit.md).
# Usage: python3 docs/ux/mocks/v2/generate.py docs/ux/mocks/v2      (needs rsvg-convert)
# Light theme (default). Navy brand sidebar + ☶ brand band, 4-item navigation, one primary action
# per screen, results carry their own undo.
import base64
import os
import subprocess
import sys

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
W, H = 1040, 680
SB = 224  # sidebar width
X0 = SB + 36  # content left
CW = W - X0 - 36  # content width
F = "font-family='Segoe UI Variable, Segoe UI, Helvetica Neue, Helvetica, Arial, sans-serif'"

T = dict(
    bg="#F4F6F9", surf="#FFFFFF", surf2="#EEF1F5", border="#E2E6EC", text="#12151B", mut="#5B6270",
    pri="#2F6BEF", pri_hover="#2459D6", prit="#2F6BEF", ok="#16935F", okT="#11804F", warn="#F5A524",
    warnT="#97590A", bad="#C62F35", badF="#FDF3F3", badS="#F3C9CB", warnF="#FFF8EB", warnS="#F2D9A6",
    okF="#EFF8F3", okS="#BFE3CF",
    n900="#0A1530", n800="#0F1E40", n700="#18295A", n600="#22407F", lam="#2F6BEF", side_text="#C3CDE3",
)
MARK = ('<path d="M112 120 Q112 104 128 104 H384 Q400 104 400 120 V178 H112 Z"/><path d="M112 216 H232 V290 H118 Q112 290 112 280 Z"/>'
        '<path d="M280 216 H400 V280 Q400 290 394 290 H280 Z"/><path d="M116 328 H232 V452 Q156 420 124 356 Z"/>'
        '<path d="M280 328 H396 L388 356 Q356 420 280 452 Z"/>')


def t(x, y, s, txt, fill=None, w=400, anchor="start", extra=""):
    return f'<text x="{x}" y="{y}" {F} font-size="{s}" font-weight="{w}" fill="{fill or T["text"]}" text-anchor="{anchor}" {extra}>{txt}</text>'


def card(x, y, w, h, fill=None, stroke=None, r=12):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill or T["surf"]}" stroke="{stroke or T["border"]}"/>'


def btn(x, y, w, label, kind="primary", h=40, on_dark=False):
    if kind == "primary":
        fill, col = ("#FFFFFF", T["n800"]) if on_dark else (T["pri"], "#FFFFFF")
        return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}"/>' + t(x + w / 2, y + h / 2 + 5, 14, label, col, 700, "middle")
    if kind == "secondary":
        if on_dark:
            return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="none" stroke="#FFFFFF" stroke-opacity=".45"/>' + t(x + w / 2, y + h / 2 + 5, 14, label, "#FFFFFF", 600, "middle")
        return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{T["surf"]}" stroke="{T["border"]}"/>' + t(x + w / 2, y + h / 2 + 5, 14, label, T["text"], 600, "middle")
    return t(x, y + h / 2 + 5, 14, label, "#FFFFFF" if on_dark else T["prit"], 600)


def status(cx, cy, r, kind):
    c = {"ok": T["ok"], "warn": T["warn"], "bad": T["bad"]}[kind]
    k = r / 26
    g = f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{c}"/>'
    if kind == "ok":
        g += f'<path d="M{cx-11*k} {cy+1*k} l{8*k} {8*k} l{15*k} {-17*k}" stroke="#fff" stroke-width="{5*k}" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
    elif kind == "warn":
        g += f'<rect x="{cx-2.5*k}" y="{cy-13*k}" width="{5*k}" height="{16*k}" rx="{2.5*k}" fill="#1A1300"/><circle cx="{cx}" cy="{cy+10*k}" r="{3*k}" fill="#1A1300"/>'
    else:
        g += f'<path d="M{cx-9*k} {cy-9*k} L{cx+9*k} {cy+9*k} M{cx+9*k} {cy-9*k} L{cx-9*k} {cy+9*k}" stroke="#fff" stroke-width="{5*k}" stroke-linecap="round"/>'
    return g


# 20 px stroke icons in one style (1.75 px stroke, round caps), the way a Lucide/Fluent set would be used.
def icon(name, x, y, col, s=20):
    k = s / 24
    p = {
        "home": "M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z",
        "file": "M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8zM14 3v5h5M9 14l2 2 4-4",
        "pc": "M3 4h18v12H3zM8 20h8M12 16v4",
        "gear": "M4 7h10M18 7h2M4 17h4M12 17h8M16 5v4M10 15v4",
        "undo": "M9 14 4 9l5-5M4 9h10a6 6 0 0 1 0 12h-3",
        "folder": "M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z",
        "usb": "M12 3v14M9 6h6M12 17a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM12 11l-4-2v-2M12 13l4-2V9",
        "power": "M12 3v8M6.3 6.3a8 8 0 1 0 11.4 0",
        "shield": "M12 3l8 3v6c0 4.4-3.4 8-8 9-4.6-1-8-4.6-8-9V6z",
        "chevron": "M9 6l6 6-6 6",
        "zalo": "M4 5h16v11H9l-4 3v-3H4z",
        "excel": "M4 4h16v16H4zM9 8l6 8M15 8l-6 8",
    }[name]
    return f'<g transform="translate({x} {y}) scale({k})" fill="none" stroke="{col}" stroke-width="{1.75/k*k}" stroke-linecap="round" stroke-linejoin="round"><path d="{p}"/></g>'


def trigram_pattern(x, y, w, h, opacity=0.07):
    """The brand motif: rows of ☶ lines (one solid, two broken) tiled across a band."""
    g = [f'<clipPath id="clip{x}{y}"><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="16"/></clipPath><g clip-path="url(#clip{x}{y})" fill="#FFFFFF" fill-opacity="{opacity}">']
    cell_w, cell_h = 72, 54
    for row in range(int(h / cell_h) + 2):
        for col in range(int(w / cell_w) + 2):
            cx = x + w - 40 - col * cell_w - (row % 2) * 36
            cy = y + 10 + row * cell_h
            if cx < x + w * 0.42:  # keep the motif on the right, behind no text
                continue
            g.append(f'<rect x="{cx}" y="{cy}" width="48" height="8" rx="4"/>')
            g.append(f'<rect x="{cx}" y="{cy+14}" width="20" height="8" rx="4"/><rect x="{cx+28}" y="{cy+14}" width="20" height="8" rx="4"/>')
            g.append(f'<rect x="{cx}" y="{cy+28}" width="20" height="8" rx="4"/><rect x="{cx+28}" y="{cy+28}" width="20" height="8" rx="4"/>')
    g.append("</g>")
    return "".join(g)


NAV = [("home", "Tổng quan"), ("file", "Kiểm tra tệp"), ("pc", "Máy của bạn"), ("gear", "Cài đặt")]


def frame(active, body, name, badge_on=None):
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
         '<defs><linearGradient id="kim" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FFFFFF"/><stop offset="0.55" stop-color="#DADDE3"/><stop offset="1" stop-color="#A9AFBA"/></linearGradient>'
         f'<linearGradient id="band" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{T["n800"]}"/><stop offset="1" stop-color="{T["n600"]}"/></linearGradient>'
         f'<linearGradient id="bandok" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{T["n800"]}"/><stop offset="1" stop-color="#1D5C6E"/></linearGradient></defs>',
         f'<rect width="{W}" height="{H}" rx="12" fill="{T["bg"]}"/>',
         f'<path d="M12 0 H{SB} V{H} H12 Q0 {H} 0 {H-12} V12 Q0 0 12 0 Z" fill="{T["n900"]}"/>',
         f'<g transform="translate(22 22) scale(0.095) translate(-96 -88)" fill="url(#kim)">{MARK}</g>',
         t(62, 50, 17, "GENRA", "#FFFFFF", 700, extra='letter-spacing="1.5"') + t(133, 50, 17, "AV", "#8E9BBA")]
    for i, (ic, label) in enumerate(NAV):
        y = 112 + i * 44
        is_active = label == active
        if is_active:
            o.append(f'<rect x="12" y="{y-26}" width="{SB-24}" height="40" rx="8" fill="{T["n700"]}"/><rect x="12" y="{y-19}" width="3" height="26" rx="1.5" fill="#6E9BFF"/>')
        col = "#FFFFFF" if is_active else T["side_text"]
        o.append(icon(ic, 28, y - 20, col) + t(58, y - 1, 14, label, col, 600 if is_active else 400))
        if badge_on == label:
            o.append(f'<circle cx="{SB-30}" cy="{y-6}" r="5" fill="{T["bad"]}"/>')
    o.append(icon("shield", 26, H - 66, "#5FD39B", 16) + t(48, H - 53, 12, "Đang canh gác", "#9FE3C1"))
    o.append(t(26, H - 30, 12, "Luật cập nhật 10 phút trước", "#8E9BBA"))
    o.append(body)
    o.append("</svg>")
    svg = "".join(o)
    open(f"{OUT}/{name}.svg", "w").write(svg)
    subprocess.run(["rsvg-convert", "-w", str(W * 2), f"{OUT}/{name}.svg", "-o", f"{OUT}/{name}.png"], check=True)


def bullet(x, y, txt, col):
    return f'<circle cx="{x+4}" cy="{y-5}" r="3" fill="{col}"/>' + t(x + 16, y, 14, txt)


def history(y0, rows, h):
    b = [card(X0, y0, CW, h), t(X0 + 20, y0 + 30, 11, "LỊCH SỬ &amp; HOÀN TÁC", T["mut"], 700, extra='letter-spacing="1"')]
    for i, (k, name, detail, action) in enumerate(rows):
        y = y0 + 52 + i * 46
        b.append(status(X0 + 32, y + 10, 11, k) + t(X0 + 54, y + 6, 14, name, w=600) + t(X0 + 54, y + 25, 12, detail, T["mut"]))
        if action:
            b.append(icon("undo", X0 + CW - 92, y - 2, T["prit"], 16) + t(X0 + CW - 20, y + 12, 13, action, T["prit"], 600, "end"))
        if i < len(rows) - 1:
            b.append(f'<line x1="{X0+20}" y1="{y+36}" x2="{X0+CW-20}" y2="{y+36}" stroke="{T["border"]}"/>')
    return "".join(b)


# 1 Tổng quan: something needs the user (one action on the brand band)
b = [t(X0, 58, 24, "Tổng quan", w=700)]
b.append(f'<rect x="{X0}" y="80" width="{CW}" height="168" rx="16" fill="url(#band)"/>' + trigram_pattern(X0, 80, CW, 168))
b.append(status(X0 + 56, 150, 30, "bad") + t(X0 + 104, 138, 22, "Có 1 việc cần xử lý", "#FFFFFF", 700)
         + t(X0 + 104, 163, 14, "Sâu lây qua Excel nằm trên máy và trong 3 tệp.", "#D7E0F5")
         + t(X0 + 104, 183, 14, "Genra dọn giúp, không làm mất gì, hoàn tác được.", "#D7E0F5")
         + btn(X0 + 104, 198, 170, "Dọn sạch giúp tôi", on_dark=True) + btn(X0 + 288, 198, 120, "Xem chi tiết", "link", on_dark=True))
b.append(history(268, [("bad", "Bieu_tong_hop.xls", "Sâu lây qua Excel · đã cách ly 09:42 · nhận qua Zalo", "Lấy lại"),
                       ("ok", "Bao_cao_thang_11.docx", "An toàn · 09:30", ""),
                       ("ok", "Quét nhanh máy", "8.476 tệp · không có mối nguy mới · 08:00", ""),
                       ("warn", "Mau_to_khai.xlsm", "Có macro tự chạy, chưa rõ hại · đã báo bạn 08:12", "")], 236))
b.append(t(X0, 534, 12, "Gợi ý: chuột phải vào tệp bất kỳ → “Kiểm tra bằng Genra AV”.", T["mut"]))
frame("Tổng quan", "".join(b), "1-tong-quan-can-xu-ly", badge_on="Máy của bạn")

# 2 Tổng quan: all good (silence is a feature)
b = [t(X0, 58, 24, "Tổng quan", w=700)]
b.append(f'<rect x="{X0}" y="80" width="{CW}" height="168" rx="16" fill="url(#bandok)"/>' + trigram_pattern(X0, 80, CW, 168))
b.append(status(X0 + 56, 150, 30, "ok") + t(X0 + 104, 140, 22, "Máy an toàn", "#FFFFFF", 700)
         + t(X0 + 104, 165, 14, "Đang canh gác Downloads, Zalo, Desktop, USB. Không cần làm gì.", "#D7E0F5")
         + btn(X0 + 104, 186, 150, "Quét nhanh máy", "secondary", on_dark=True))
for i, (h, v, sub) in enumerate([("Tệp đã kiểm tra", "8.476", "lần quét gần nhất 08:00"), ("Đã chặn", "3", "tuần này"), ("Đã dọn", "1", "hoàn tác được 29 ngày")]):
    x = X0 + i * (CW + 16) / 3
    w = (CW - 32) / 3
    b.append(card(x, 268, w, 92) + t(x + 18, 294, 12, h, T["mut"]) + t(x + 18, 328, 26, v, w=700) + t(x + 18, 348, 12, sub, T["mut"]))
b.append(card(X0, 380, CW, 150) + t(X0 + 20, 410, 11, "SỨC KHOẺ MÁY", T["mut"], 700, extra='letter-spacing="1"'))
for i, (k, txt) in enumerate([("ok", "Windows Defender đang bật và mới"), ("ok", "Excel chỉ chạy macro của tệp tin cậy"), ("ok", "Không có chương trình lạ khởi động cùng máy")]):
    y = 438 + i * 30
    b.append(status(X0 + 30, y - 5, 9, k) + t(X0 + 48, y, 14, txt))
frame("Tổng quan", "".join(b), "2-tong-quan-an-toan")

# 3 Kiểm tra tệp: threat, one end-to-end action
b = [t(X0, 58, 24, "Kiểm tra tệp", w=700)]
b.append(card(X0, 80, CW, 448, fill=T["badF"], stroke=T["badS"], r=16) + status(X0 + 56, 140, 30, "bad")
         + t(X0 + 104, 126, 12, "MÃ ĐỘC", T["bad"], 700, extra='letter-spacing="1"') + t(X0 + 104, 152, 22, "Tệp này có sâu lây qua Excel", w=700)
         + t(X0 + 104, 176, 14, "Bieu_tong_hop.xls · nhận qua Zalo lúc 09:41", T["mut"]))
b.append(t(X0 + 104, 214, 12, "NÓ LÀM GÌ", T["mut"], 700, extra='letter-spacing="1"'))
for i, txt in enumerate(["Tự chép vào Excel trên máy bạn", "Lây sang mọi tệp Excel bạn mở sau đó", "Đổi .xlsx thành .xls, có thể mất dữ liệu ở bảng lớn"]):
    b.append(bullet(X0 + 104, 240 + i * 24, txt, T["bad"]))
b.append(card(X0 + 104, 324, CW - 140, 104, fill=T["surf"], r=10) + t(X0 + 122, 350, 12, "MỘT NÚT, GENRA LÀM HẾT", T["mut"], 700, extra='letter-spacing="1"'))
for i, txt in enumerate(["Thay tệp này bằng bản sạch, giữ nguyên dữ liệu (bản gốc giữ 30 ngày)",
                         "Gỡ sâu khỏi Excel và làm sạch các tệp đã bị lây", "Kiểm tra lại: mọi tệp mở bình thường"]):
    b.append(icon("chevron", X0 + 118, 360 + i * 22, T["pri"], 14) + t(X0 + 138, 372 + i * 22, 13, txt))
b.append(btn(X0 + 104, 448, 200, "Dọn sạch giúp tôi") + btn(X0 + 320, 448, 120, "Xem chi tiết", "link"))
b.append(t(X0 + CW - 20, 474, 12, "Tệp này an toàn? Báo nhầm", T["mut"], anchor="end", extra='text-decoration="underline"'))
frame("Kiểm tra tệp", "".join(b), "3-ket-qua-ma-doc")

# 4 Excel is open: Genra asks Excel to close itself (one extra press, never kills unsaved work)
b = [t(X0, 58, 24, "Kiểm tra tệp", w=700), f'<rect x="{SB}" y="0" width="{W-SB}" height="{H}" fill="#0A1530" fill-opacity=".38"/>',
     f'<rect x="{SB+24}" y="0" width="0" height="0"/>']
dx, dy, dw, dh = X0 + 70, 150, CW - 140, 300
b.append(f'<rect x="{dx}" y="{dy}" width="{dw}" height="{dh}" rx="14" fill="{T["surf"]}" stroke="{T["border"]}"/>')
b.append(icon("excel", dx + 28, dy + 30, "#1D6F42", 28) + t(dx + 70, dy + 50, 18, "Cần đóng Excel trước khi dọn", w=700))
b.append(t(dx + 70, dy + 80, 14, "Excel đang mở 1 tệp: Ke_hoach_2027.xlsx.", T["mut"]) + t(dx + 70, dy + 102, 14, "Genra sẽ nhờ Excel đóng lại; nếu tệp chưa lưu, Excel sẽ hỏi bạn lưu.", T["mut"]))
b.append(t(dx + 70, dy + 124, 14, "Genra không bao giờ tự tắt Excel khi bạn còn việc chưa lưu.", T["mut"]))
b.append(card(dx + 70, dy + 146, dw - 100, 56, fill=T["surf2"], r=8) + status(dx + 92, dy + 174, 9, "ok") + t(dx + 110, dy + 179, 13, "Sau khi Excel đóng, Genra tự dọn tiếp. Bạn không cần bấm gì thêm."))
b.append(btn(dx + 70, dy + 228, 190, "Đóng Excel giúp tôi") + btn(dx + 276, dy + 228, 150, "Để tôi tự đóng", "secondary"))
frame("Kiểm tra tệp", "".join(b), "4-dong-excel")

# 5 Done, verified, with undo right here
b = [t(X0, 58, 24, "Kiểm tra tệp", w=700)]
b.append(card(X0, 80, CW, 400, fill=T["surf"], r=16) + status(X0 + 56, 140, 30, "ok") + t(X0 + 104, 136, 22, "Đã dọn sạch máy và tệp", w=700)
         + t(X0 + 104, 161, 14, "Máy hoạt động bình thường. Dữ liệu của bạn giữ nguyên.", T["mut"]))
for i, (a, d) in enumerate([("Gỡ sâu khỏi Excel", "XLSTART › mypersonnel.xls đã vào khu cách ly"),
                            ("Làm sạch 3 tệp Excel", "Bieu_tong_hop.xls và 2 tệp khác, thay tại chỗ"),
                            ("Kiểm tra lại", "Excel mở bình thường · tệp sạch khớp bản gốc 81 dòng × 13 cột")]):
    y = 204 + i * 50
    b.append(status(X0 + 114, y - 4, 10, "ok") + t(X0 + 134, y, 14, a, w=600) + t(X0 + 134, y + 20, 12, d, T["mut"]))
b.append(card(X0 + 104, 362, CW - 140, 54, fill=T["surf2"], r=10) + icon("zalo", X0 + 120, 378, T["mut"]) + t(X0 + 150, 394, 13, "Nên báo người gửi tệp qua Zalo dọn máy của họ. Genra soạn sẵn lời nhắn cho bạn."))
b.append(btn(X0 + 104, 428, 170, "Soạn lời nhắn") + icon("undo", X0 + 300, 438, T["prit"], 18) + btn(X0 + 324, 428, 100, "Hoàn tác", "link"))
frame("Kiểm tra tệp", "".join(b), "5-da-don-xong")

# 6 Máy của bạn: health + startup + guarded folders in one place
b = [t(X0, 58, 24, "Máy của bạn", w=700), t(X0, 82, 14, "1 việc nên sửa. Mọi thay đổi hoàn tác được.", T["mut"])]
b.append(card(X0, 100, CW, 62, fill=T["warnF"], stroke=T["warnS"]) + status(X0 + 32, 131, 13, "warn") + t(X0 + 56, 126, 15, "Excel đang cho chạy mọi macro", w=600)
         + t(X0 + 56, 147, 13, "Tệp lạ có macro sẽ tự chạy khi mở. Chỉ nên chạy macro của tệp tin cậy.", T["mut"]) + btn(X0 + CW - 150, 112, 134, "Sửa giúp tôi", h=38))
b.append(card(X0, 176, CW, 176) + t(X0 + 20, 204, 11, "KHỞI ĐỘNG CÙNG MÁY", T["mut"], 700, extra='letter-spacing="1"'))
for i, (k, name, d, act) in enumerate([("bad", "mypersonnel.xls (XLSTART)", "Sâu Kangatang · đã gỡ, hoàn tác được", "Lấy lại"),
                                       ("ok", "OneDrive", "Microsoft · đã ký", ""), ("ok", "Zalo", "VNG · đã ký", ""), ("warn", "updater.exe (AppData)", "Không có chữ ký · chạy từ 18/11", "Tắt")]):
    y = 228 + i * 30
    b.append(status(X0 + 30, y - 4, 8, k) + t(X0 + 48, y, 13, name, w=600) + t(X0 + 290, y, 12, d, T["mut"]))
    if act:
        b.append(t(X0 + CW - 20, y, 13, act, T["prit"], 600, "end"))
b.append(card(X0, 366, CW, 150) + t(X0 + 20, 394, 11, "ĐANG CANH GÁC", T["mut"], 700, extra='letter-spacing="1"'))
for i, (ic, name, d) in enumerate([("folder", "Downloads", "Tệp mới được kiểm tra ngay khi tải về"), ("zalo", "Zalo Received Files", "Tệp nhận qua Zalo"),
                                   ("usb", "Ổ USB", "Kiểm tra khi cắm vào · đang cắm: KINGSTON (E:)")]):
    y = 420 + i * 30
    b.append(icon(ic, X0 + 22, y - 16, T["mut"], 18) + t(X0 + 50, y, 13, name, w=600) + t(X0 + 290, y, 12, d, T["mut"]))
frame("Máy của bạn", "".join(b), "6-may-cua-ban")

# 7 Notification: the guard reaches the user with the fix and the undo on it (0 steps to find it)
o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
     '<defs><linearGradient id="desk" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#C9D6EA"/><stop offset="1" stop-color="#E8EEF6"/></linearGradient>'
     '<linearGradient id="kim" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3A3F4A"/><stop offset="1" stop-color="#15171C"/></linearGradient></defs>',
     f'<rect width="{W}" height="{H}" rx="12" fill="url(#desk)"/>', f'<rect x="0" y="{H-48}" width="{W}" height="48" fill="#F3F5F8" fill-opacity=".92"/>',
     t(W - 30, H - 18, 12, "09:41", T["text"], anchor="end")]
nx, ny, nw, nh = W - 392, H - 246, 368, 186
o.append(f'<rect x="{nx}" y="{ny}" width="{nw}" height="{nh}" rx="10" fill="#FFFFFF" stroke="#D6DCE5"/>')
o.append(f'<g transform="translate({nx+16} {ny+16}) scale(0.05) translate(-96 -88)" fill="url(#kim)">{MARK}</g>' + t(nx + 40, ny + 29, 12, "Genra AV", T["mut"]))
o.append(status(nx + 30, ny + 66, 12, "bad") + t(nx + 52, ny + 62, 14, "Đã chặn tệp nhiễm sâu từ Zalo", w=700) + t(nx + 52, ny + 82, 13, "Bieu_tong_hop.xls · đã cách ly, chưa mở", T["mut"]))
o.append(t(nx + 52, ny + 102, 13, "Máy có thể đã nhiễm. Dọn mất khoảng 1 phút.", T["mut"]))
o.append(btn(nx + 16, ny + 124, 160, "Dọn sạch giúp tôi", h=40) + btn(nx + 186, ny + 124, 166, "Để sau", "secondary", h=40))
o.append(t(36, 56, 16, "Thông báo của Windows khi Genra chặn một tệp (0 bước để tìm ra vấn đề)", T["text"], 600))
o.append("</svg>")
open(f"{OUT}/7-thong-bao.svg", "w").write("".join(o))
subprocess.run(["rsvg-convert", "-w", str(W * 2), f"{OUT}/7-thong-bao.svg", "-o", f"{OUT}/7-thong-bao.png"], check=True)

# overview sheet
names = ["1-tong-quan-can-xu-ly", "2-tong-quan-an-toan", "3-ket-qua-ma-doc", "4-dong-excel", "5-da-don-xong", "6-may-cua-ban", "7-thong-bao"]
labels = ["1 Tổng quan: cần xử lý (1 nút)", "2 Tổng quan: máy an toàn", "3 Kết quả: mã độc → Dọn sạch giúp tôi", "4 Excel đang mở: Genra nhờ Excel đóng",
          "5 Đã dọn xong, hoàn tác ngay tại chỗ", "6 Máy của bạn: sức khoẻ + khởi động + canh gác", "7 Thông báo mang sẵn nút sửa"]
parts = []
for i, (n, l) in enumerate(zip(names, labels)):
    x = 40 + (i % 2) * 1080
    y = 40 + (i // 2) * 760
    d = base64.b64encode(open(f"{OUT}/{n}.png", "rb").read()).decode()
    parts.append(f'<image x="{x}" y="{y}" width="{W}" height="{H}" href="data:image/png;base64,{d}"/><text x="{x}" y="{y+H+36}" font-family="Helvetica" font-size="22" font-weight="600" fill="#2A2E36">{l}</text>')
rows = (len(names) + 1) // 2
tmp = f"{OUT}/_overview.svg"
open(tmp, "w").write(f'<svg xmlns="http://www.w3.org/2000/svg" width="2200" height="{rows*760+40}"><rect width="2200" height="{rows*760+40}" fill="#E4E6EA"/>' + "".join(parts) + "</svg>")
subprocess.run(["rsvg-convert", tmp, "-o", f"{OUT}/overview.png"], check=True)
os.remove(tmp)
