# Mock-up generator for docs/ux/mocks/v1 (tokens from docs/design/tokens.md).
# Usage: python3 docs/ux/mocks/v1/generate.py docs/ux/mocks/v1 light|dark   (needs rsvg-convert)
import subprocess, sys, os, base64
OUT=sys.argv[1]; THEME=sys.argv[2] if len(sys.argv)>2 else "light"
THEMES={
 "light":dict(bg="#F6F7F9",side="#FFFFFF",surf="#FFFFFF",surf2="#EEF0F3",border="#E3E6EB",text="#12151B",mut="#5B6270",pri="#2F6BEF",prit="#2F6BEF",ok="#16935F",warn="#F5A524",bad="#C62F35",
   dz="#F9FAFC",dangF="#FDF3F3",dangS="#F3C9CB",warnF="#FFF8EB",warnS="#F2D9A6",infoF="#EEF3FE",infoS="#C6D6FB",disF="#DCE5FB",disT="#7D93C4",okT="#11804F",mark="ink"),
 "dark":dict(bg="#0F1115",side="#0B0D11",surf="#171A21",surf2="#1F232C",border="#2A2F3A",text="#F2F4F7",mut="#A3AAB8",pri="#2F6BEF",prit="#6E9BFF",ok="#2EBD85",warn="#F5A524",bad="#D93A40",
   dz="#11161C",dangF="#1C1416",dangS="#4A2226",warnF="#1E1A12",warnS="#5A4416",infoF="#121A2B",infoS="#24407A",disF="#22314F",disT="#8FA3C8",okT="#2EBD85",mark="kim"),
}
T=THEMES[THEME]; OUT=f"{OUT}/{THEME}"; os.makedirs(OUT,exist_ok=True)
F="font-family='Helvetica Neue, Helvetica, Arial, sans-serif'"
P='<path d="M112 120 Q112 104 128 104 H384 Q400 104 400 120 V178 H112 Z"/><path d="M112 216 H232 V290 H118 Q112 290 112 280 Z"/><path d="M280 216 H400 V280 Q400 290 394 290 H280 Z"/><path d="M116 328 H232 V452 Q156 420 124 356 Z"/><path d="M280 328 H396 L388 356 Q356 420 280 452 Z"/>'
W,H=960,620; X0=232
def t(x,y,s,txt,fill=None,w=400,anchor="start",extra=""):
    return f'<text x="{x}" y="{y}" {F} font-size="{s}" font-weight="{w}" fill="{fill or T["text"]}" text-anchor="{anchor}" {extra}>{txt}</text>'
def card(x,y,w,h,fill=None,stroke=None,r=12): return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill or T["surf"]}" stroke="{stroke or T["border"]}"/>'
def btn(x,y,w,label,kind="primary",h=40):
    if kind=="primary": return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{T["pri"]}"/>'+t(x+w/2,y+h/2+5,14,label,"#FFFFFF",700,"middle")
    if kind=="secondary": return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{T["surf2"]}" stroke="{T["border"]}"/>'+t(x+w/2,y+h/2+5,14,label,T["text"],600,"middle")
    return t(x,y+h/2+5,14,label,T["prit"],600)
def ico(cx,cy,r,kind):
    c={"ok":T["ok"],"warn":T["warn"],"bad":T["bad"]}[kind]
    g=f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{c}"/>'
    k=r/26
    if kind=="ok": g+=f'<path d="M{cx-11*k} {cy+1*k} l{8*k} {8*k} l{15*k} {-17*k}" stroke="#fff" stroke-width="{5*k}" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
    elif kind=="warn": g+=f'<rect x="{cx-2.5*k}" y="{cy-13*k}" width="{5*k}" height="{16*k}" rx="{2.5*k}" fill="#0F1115"/><circle cx="{cx}" cy="{cy+10*k}" r="{3*k}" fill="#0F1115"/>'
    else: g+=f'<path d="M{cx-9*k} {cy-9*k} L{cx+9*k} {cy+9*k} M{cx+9*k} {cy-9*k} L{cx-9*k} {cy+9*k}" stroke="#fff" stroke-width="{5*k}" stroke-linecap="round"/>'
    return g
def bullet(x,y,txt,kind=None,col=None):
    dot=f'<circle cx="{x+4}" cy="{y-5}" r="3" fill="{col or T["mut"]}"/>'
    return dot+t(x+16,y,14,txt,T["text"])
def frame(active,body,name):
    o=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
       '<defs><linearGradient id="kim" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FFFFFF"/><stop offset="0.55" stop-color="#DADDE3"/><stop offset="1" stop-color="#A9AFBA"/></linearGradient><linearGradient id="ink" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3A3F4A"/><stop offset="1" stop-color="#15171C"/></linearGradient></defs>',
       f'<rect width="{W}" height="{H}" rx="12" fill="{T["bg"]}"/>',
       f'<path d="M12 0 H204 V{H} H12 Q0 {H} 0 {H-12} V12 Q0 0 12 0 Z" fill="{T["side"]}"/><line x1="204" y1="0" x2="204" y2="{H}" stroke="{T["border"]}"/>',
       f'<g transform="translate(20 22) scale(0.095) translate(-96 -88)" fill="url(#{T["mark"]})">{P}</g>',
       t(60,50,17,"GENRA",T["text"],700,extra='letter-spacing="1.5"')+t(131,50,17,"AV",T["mut"])]
    items=["Tổng quan","Kiểm tra tệp","Dọn máy","Sức khoẻ máy","Đã cách ly","Cài đặt"]
    for i,it in enumerate(items):
        y=104+i*40
        if it==active: o.append(f'<rect x="12" y="{y-24}" width="180" height="36" rx="8" fill="{T["surf2"]}"/><rect x="12" y="{y-17}" width="3" height="22" rx="1.5" fill="{T["pri"]}"/>')
        o.append(t(30,y,14,it,T["text"] if it==active else T["mut"],600 if it==active else 400))
        if it=="Dọn máy" and active not in ("Dọn máy",): o.append(f'<circle cx="176" cy="{y-5}" r="5" fill="{T["bad"]}"/>' if name in ("1-tong-quan","3-ket-qua-nguy-hiem") else "")
    o.append(t(30,H-48,12,"● Đang canh gác 5 thư mục",T["okT"]))
    o.append(t(30,H-26,12,"Luật cập nhật 10 phút trước",T["mut"]))
    o.append(body); o.append('</svg>')
    svg="".join(o); open(f"{OUT}/{name}.svg","w").write(svg)
    subprocess.run(["rsvg-convert","-w",str(W*2),f"{OUT}/{name}.svg","-o",f"{OUT}/{name}.png"],check=True)

# 1 Tổng quan
b=[t(X0,62,24,"Tổng quan",w=700)]
b.append(card(X0,84,696,152,fill=T["dangF"],stroke=T["dangS"],r=16)+ico(X0+56,150,30,"bad")+t(X0+104,136,22,"Có 1 việc cần xử lý",w=700)+t(X0+104,162,14,"Sâu lây qua Excel đang nằm trên máy. Genra gỡ giúp, không làm mất gì.",T["mut"])+btn(X0+104,176,150,"Dọn giúp tôi")+btn(X0+272,176,140,"Kiểm tra tệp","secondary"))
for i,(h,v) in enumerate([("Tệp đã kiểm tra","1.284"),("Đã chặn","3"),("Đã dọn","1")]):
    x=X0+i*236; b.append(card(x,252,224,80)+t(x+16,278,12,h,T["mut"])+t(x+16,314,26,v,w=700))
b.append(card(X0,348,696,240)+t(X0+20,376,11,"GẦN ĐÂY",T["mut"],700,extra='letter-spacing="1"'))
rows=[("bad","Bieu_tong_hop.xls","Sâu lây qua Excel · đã cách ly 09:42","Xem"),("ok","Bao_cao_thang_11.docx","An toàn · 09:30",""),("ok","Danh_sach_ho_ngheo.xlsx","An toàn · 08:55",""),("warn","Mau_to_khai.xlsm","Có macro tự chạy, chưa rõ hại · 08:12","Xem")]
for i,(k,n,d,a) in enumerate(rows):
    y=396+i*46; b.append(ico(X0+34,y+12,11,k)+t(X0+58,y+8,14,n,w=600)+t(X0+58,y+27,12,d,T["mut"])+(t(X0+676,y+16,13,a,T["prit"],600,"end") if a else ""))
    if i<3: b.append(f'<line x1="{X0+20}" y1="{y+38}" x2="{X0+676}" y2="{y+38}" stroke="{T["border"]}"/>')
frame("Tổng quan","".join(b),"1-tong-quan")

# 2 Kết quả: an toàn
b=[t(X0,62,24,"Kiểm tra tệp",w=700)]
b.append(card(X0,84,696,130,fill=T["dz"],stroke=T["border"],r=16)+f'<rect x="{X0+1}" y="85" width="694" height="128" rx="15" fill="none" stroke="{T["pri"]}" stroke-dasharray="7 6" opacity=".7"/>'+t(X0+348,140,17,"Kéo tệp vào đây để kiểm tra",w=600,anchor="middle")+t(X0+348,166,13,"Tệp không bị gửi đi đâu. Excel, Word, PowerPoint, PDF, tệp nén…",T["mut"],anchor="middle")+btn(X0+290,180,116,"Chọn tệp","link",24))
b.append(card(X0,232,696,250,r=16)+ico(X0+60,300,32,"ok")+t(X0+112,290,22,"Tệp này an toàn",w=700)+t(X0+112,316,14,"Danh_sach_ho_ngheo.xlsx · 48 KB",T["mut"]))
b.append(t(X0+112,360,13,"ĐÃ KIỂM TRA",T["mut"],700,extra='letter-spacing="1"'))
b.append(bullet(X0+112,388,"Không có macro hay mã tự chạy",col=T["ok"])+bullet(X0+112,414,"Không khớp mẫu mã độc nào (luật mới nhất 10 phút trước)",col=T["ok"]))
b.append(btn(X0+112,432,160,"Mở thư mục","secondary")+btn(X0+290,432,170,"Kiểm tra tệp khác","secondary"))
frame("Kiểm tra tệp","".join(b),"2-ket-qua-an-toan")

# 3 Kết quả: nguy hiểm — one button cleans the file AND the machine
b=[t(X0,62,24,"Kiểm tra tệp",w=700)]
b.append(card(X0,84,696,480,fill=T["dangF"],stroke=T["dangS"],r=16)+ico(X0+60,148,32,"bad")+t(X0+112,138,22,"Tệp này có mã độc",w=700)+t(X0+112,164,14,"Bieu_tong_hop.xls · Sâu lây qua Excel (Kangatang)",T["mut"]))
b.append(t(X0+112,206,13,"NÓ LÀM GÌ",T["mut"],700,extra='letter-spacing="1"'))
b.append(bullet(X0+112,232,"Tự chép vào Excel trên máy bạn",col=T["bad"])+bullet(X0+112,256,"Lây sang mọi tệp Excel bạn mở sau đó",col=T["bad"])+bullet(X0+112,280,"Đổi tệp .xlsx thành .xls, có thể mất dữ liệu ở bảng lớn",col=T["bad"]))
b.append(t(X0+112,312,13,"✓ Đã cách ly tệp gốc, lấy lại được trong 30 ngày.",T["okT"]))
b.append(card(X0+112,330,560,132,fill=T["surf"],stroke=T["border"],r=10)+t(X0+130,356,13,"GENRA SẼ DỌN GIÚP BẠN",T["mut"],700,extra='letter-spacing="1"'))
for i,txt in enumerate(["Làm sạch tệp này (giữ nguyên dữ liệu)","Gỡ sâu khỏi Excel trên máy","Tìm và làm sạch các tệp Excel khác đã bị lây","Kiểm tra lại: Excel và các tệp mở bình thường"]):
    y=380+i*22; b.append(t(X0+130,y,13,f"{i+1}.",T["mut"],700)+t(X0+150,y,13,txt))
b.append(t(X0+112,484,12,"Không đụng gì khác. Hoàn tác được trong 30 ngày.",T["mut"]))
b.append(btn(X0+112,500,190,"Dọn sạch giúp tôi")+btn(X0+318,500,140,"Xem chi tiết","secondary"))
b.append(t(X0+676,516,13,"Chỉ làm sạch tệp này",T["prit"],600,"end")+t(X0+676,540,12,"Tệp này an toàn, báo nhầm",T["mut"],anchor="end",extra='text-decoration="underline"'))
frame("Kiểm tra tệp","".join(b),"3-ket-qua-nguy-hiem")

# 4 Đã dọn xong — machine + files, verified
b=[t(X0,62,24,"Dọn máy",w=700)]
b.append(card(X0,84,696,470,r=16)+ico(X0+60,148,32,"ok")+t(X0+112,138,22,"Đã dọn sạch máy và tệp",w=700)+t(X0+112,164,14,"Máy hoạt động bình thường. Dữ liệu của bạn giữ nguyên.",T["mut"]))
b.append(t(X0+112,206,13,"ĐÃ LÀM",T["mut"],700,extra='letter-spacing="1"'))
done=[("Gỡ sâu Kangatang khỏi Excel","Đã cách ly XLSTART › mypersonnel.xls"),("Làm sạch 3 tệp Excel bị lây","Bieu_tong_hop.xls và 2 tệp khác, bản gốc ở Đã cách ly"),("Kiểm tra lại","Excel mở bình thường · tệp sạch khớp bản gốc (dòng, cột, trang tính)")]
for i,(x1,x2) in enumerate(done):
    y=236+i*50; b.append(ico(X0+122,y-4,10,"ok")+t(X0+142,y,14,x1,w=600)+t(X0+142,y+20,12,x2,T["mut"]))
b.append(card(X0+112,388,560,62,fill=T["surf2"],r=10)+t(X0+130,412,12,"BẢN SẠCH",T["mut"],700,extra='letter-spacing="1"')+t(X0+130,436,14,"Tài liệu › Genra › Bản sạch (3 tệp)",w=600))
b.append(t(X0+112,476,13,"Nên làm tiếp: gửi bản sạch cho người đã gửi tệp, và báo họ dọn máy.",T["text"]))
b.append(btn(X0+112,494,190,"Mở thư mục bản sạch")+btn(X0+318,494,120,"Hoàn tác","link"))
frame("Dọn máy","".join(b),"4-da-don-xong")

# 5 Dọn máy
b=[t(X0,62,24,"Dọn máy",w=700)]
b.append(card(X0,84,696,214,r=16)+ico(X0+56,140,28,"bad")+t(X0+104,132,20,"Tìm thấy 1 mã độc trên máy",w=700)+t(X0+104,156,14,"Genra sẽ làm 3 việc dưới đây. Không đụng gì khác, hoàn tác được trong 30 ngày.",T["mut"]))
steps=[("Gỡ sâu Kangatang khỏi Excel","XLSTART › mypersonnel.xls → chuyển vào khu cách ly"),("Làm sạch 3 tệp Excel bị lây","Giữ bản gốc trong khu cách ly"),("Kiểm tra lại toàn bộ","Mở thử các tệp, quét lại thư mục khởi động")]
for i,(a,d) in enumerate(steps):
    y=196+i*34; b.append(f'<circle cx="{X0+116}" cy="{y-5}" r="11" fill="{T["surf2"]}" stroke="{T["border"]}"/>'+t(X0+116,y,12,str(i+1),w=700,anchor="middle")+t(X0+138,y,14,a,w=600)+t(X0+380,y,12,d,T["mut"]))
b.append(card(X0,314,696,96,fill=T["infoF"],stroke=T["infoS"],r=14)+t(X0+24,346,15,"Cần đóng Excel trước khi dọn",w=700)+t(X0+24,370,13,"Excel đang mở 1 tệp chưa lưu: Ke_hoach_2027.xlsx. Hãy lưu lại, Genra sẽ chờ.",T["mut"])+t(X0+24,394,13,"Genra không tự đóng Excel khi bạn còn việc chưa lưu.",T["mut"]))
b.append('<rect x="'+str(X0)+'" y="430" width="170" height="40" rx="8" fill="'+T["disF"]+'"/>'+t(X0+85,455,14,"Dọn giúp tôi",T["disT"],700,"middle")+t(X0+186,455,13,"Chờ bạn lưu và đóng Excel…",T["mut"])+btn(X0+560,430,136,"Xem chi tiết","secondary"))
b.append(t(X0,520,12,"Lần dọn trước: chưa có. Mọi thay đổi được ghi lại và hoàn tác được trong mục Đã cách ly.",T["mut"]))
frame("Dọn máy","".join(b),"5-don-may")

# 6 Sức khoẻ máy
b=[t(X0,62,24,"Sức khoẻ máy",w=700),t(X0,88,14,"4 mục ổn, 1 mục nên sửa.",T["mut"])]
items=[("ok","Windows Defender đang bật","Cập nhật lúc 07:15 hôm nay",""),("ok","Luật của Genra mới nhất","Phiên bản 2026112601 · 10 phút trước",""),("warn","Excel đang cho chạy mọi macro","Tệp lạ có macro sẽ tự chạy khi mở. Nên tắt, chỉ bật cho tệp tin cậy.","Sửa giúp tôi"),("ok","Canh gác 5 thư mục","Downloads, Zalo, Desktop, XLSTART, ổ USB",""),("ok","Windows đã cập nhật","Bản vá gần nhất 18/11","")]
for i,(k,a,d,act) in enumerate(items):
    y=108+i*88; hi=k=="warn"
    b.append(card(X0,y,696,76,fill=T["warnF"] if hi else T["surf"],stroke=T["warnS"] if hi else T["border"])+ico(X0+36,y+38,14,k)+t(X0+64,y+33,15,a,w=600)+t(X0+64,y+55,13,d,T["mut"]))
    if act: b.append(btn(X0+540,y+19,136,act,h=38))
frame("Sức khoẻ máy","".join(b),"6-suc-khoe-may")
