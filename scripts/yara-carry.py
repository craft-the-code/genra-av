#!/usr/bin/env python3
"""The signing job's fallback when this run's YARA rules cannot be confirmed (the rebuild failed,
the sources went back or diverged): put the previous signed pack's YARA entry and file into the
unsigned pack instead, or drop YARA when the previous pack had none. The hash lists then still go
out; check-pack.py verifies the carried entry against the previous signed pack. Standard library.

Usage: yara-carry.py <out/pack.json> <prev-dir>
"""
import json
import os
import re
import shutil
import sys


def main() -> None:
    pack_path, prev_dir = sys.argv[1:3]
    pack = json.load(open(pack_path, encoding="utf-8"))
    prev_path = os.path.join(prev_dir, "pack.json")
    prev = json.load(open(prev_path, encoding="utf-8")) if os.path.exists(prev_path) else {}
    old = pack.pop("yara", None)
    if old and re.fullmatch(r"yara-[0-9a-f]{12}\.yar", old.get("file", "")):
        try:
            os.remove(os.path.join(os.path.dirname(pack_path), old["file"]))
        except FileNotFoundError:
            pass
    y = prev.get("yara")
    if y:
        if not re.fullmatch(r"yara-[0-9a-f]{12}\.yar", y["file"]):
            sys.exit("yara-carry: odd previous YARA file name")
        shutil.copyfile(os.path.join(prev_dir, y["file"]), os.path.join(os.path.dirname(pack_path), y["file"]))
        pack["yara"] = y
        print(f"yara-carry: kept the previous signed rules {y['file']}")
    else:
        print("yara-carry: no previous rules; this pack carries none")
    with open(pack_path, "w", encoding="utf-8") as f:
        json.dump(pack, f, ensure_ascii=False, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
