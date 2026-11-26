#!/usr/bin/env python3
"""Compose a rule pack JSON from the hand-written rules and a built hash list.

Usage: build-pack.py <rules/base.json> <hash-list.bin> <out/pack.json>

The pack version is the UTC time as YYYYMMDDHH, so it only grows (clients refuse older packs).
The hash list is named with its SHA-256 so the pack signature covers it (ADR 0002).
"""
import datetime
import hashlib
import json
import os
import sys


def main() -> None:
    rules_path, hashes_path, out_path = sys.argv[1:4]
    pack = json.load(open(rules_path, encoding="utf-8"))
    digest = hashlib.sha256(open(hashes_path, "rb").read()).hexdigest()
    now = datetime.datetime.now(datetime.timezone.utc)
    version = int(now.strftime("%Y%m%d%H"))
    if version <= int(pack.get("version", 0)):
        version = int(pack["version"]) + 1
    pack["version"] = version
    pack["published"] = now.strftime("%Y-%m-%dT%H:%MZ")
    pack["hash_sets"] = [
        {
            "file": os.path.basename(hashes_path),
            "sha256": digest,
            "family": "Mã độc đã biết",
            "severity": "malware",
            "source": "abuse.ch MalwareBazaar",
        }
    ]
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(pack, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"pack version {version}, hash list {digest[:16]}…")


if __name__ == "__main__":
    main()
