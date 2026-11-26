#!/usr/bin/env python3
"""Print every SHA-256 found in a MalwareBazaar CSV export (stdin), one per line.

The export has `#` comment lines and quoted columns; rather than trust a column index that
may change, take every 64-hex-character field.
"""
import re
import sys

HEX64 = re.compile(r"^[0-9a-f]{64}$")

for line in sys.stdin:
    if line.startswith("#"):
        continue
    for field in line.split(","):
        value = field.strip().strip('"').lower()
        if HEX64.match(value):
            print(value)
