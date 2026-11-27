#!/usr/bin/env python3
"""Write ordinary Office files without macros for the false-positive corpus.

Usage: make_clean_office.py <out-dir> <count>   (needs python-docx and openpyxl)

Half Word, half Excel, with Vietnamese text, tables, formulas and a hidden sheet, the things office
files really carry. Genra must not flag any of them.
"""
import os
import random
import sys

import docx
import openpyxl

WORDS = "báo cáo tổng hợp kết quả công tác tháng quý năm đơn vị phường xã danh sách kế hoạch".split()


def sentence(r: random.Random) -> str:
    return " ".join(r.choice(WORDS) for _ in range(r.randint(6, 14))).capitalize() + "."


def main() -> None:
    out, n = sys.argv[1], int(sys.argv[2])
    os.makedirs(out, exist_ok=True)
    r = random.Random(4)
    for i in range(n):
        if i % 2 == 0:
            d = docx.Document()
            d.add_heading(sentence(r), level=1)
            for _ in range(r.randint(2, 8)):
                d.add_paragraph(sentence(r))
            t = d.add_table(rows=3, cols=3)
            for row in t.rows:
                for c in row.cells:
                    c.text = r.choice(WORDS)
            d.save(os.path.join(out, f"van-ban-{i}.docx"))
        else:
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Tong hop"
            for row in range(1, r.randint(5, 40)):
                ws.cell(row=row, column=1, value=sentence(r))
                ws.cell(row=row, column=2, value=r.randint(0, 10_000))
            ws.cell(row=50, column=2, value="=SUM(B1:B49)")
            hidden = wb.create_sheet("An")
            hidden["A1"] = "du lieu phu"
            hidden.sheet_state = "hidden"
            wb.save(os.path.join(out, f"bang-tinh-{i}.xlsx"))


if __name__ == "__main__":
    main()
