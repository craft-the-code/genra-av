#!/usr/bin/env python3
"""Compose the unsigned rule pack JSON from the hand-written rules and a built hash list.

Usage: build-pack.py <rules/base.json> <feed.bin> <trusted.bin> <prev-version> <out-dir> [<yara.json>]

- version = max(previous published version + 1, UTC time as YYYYMMDDHH, base.json's version),
  so it only grows (clients refuse an older pack, or the same version with other bytes).
- expires = now + 14 days: a client refuses the pack after that, so blocking updates cannot keep
  a machine on an old pack forever.
- The hash list is copied to <out-dir>/malwarebazaar-<version>.bin and named in the pack with its
  SHA-256 and entry count, so the one signature over the JSON covers it (ADR 0002). A versioned
  name means a published pack never points at a file that a later run replaces.
- A public feed is `suspicious` and not `trusted`: a match alone never quarantines.
- The trusted list (scripts/hash_grade.py: listed family, corroborated by other engines, 48 hours
  old) is `malware` and `trusted`, copied to trusted-<version>.bin and listed first, so a hash on
  both lists is looked up as trusted. An empty trusted list is left out.
- YARA rules: <yara.json> (from scripts/yara-build.sh, the file already in <out-dir>) is named in
  the pack as `yara`; the signing job rebuilds the file itself and compares.
Writes <out-dir>/pack.json and prints the version.
"""
import datetime
import hashlib
import json
import os
import shutil
import sys

EXPIRY_DAYS = 14


def main() -> None:
    rules_path, hashes_path, trusted_path, prev_version, out_dir = sys.argv[1:6]
    yara_path = sys.argv[6] if len(sys.argv) > 6 else None
    with open(rules_path, encoding="utf-8") as f:
        pack = json.load(f)
    with open(hashes_path, "rb") as f:
        data = f.read()
    if len(data) % 32:
        sys.exit("hash list length is not a multiple of 32")
    now = datetime.datetime.now(datetime.timezone.utc)
    version = max(int(prev_version) + 1, int(now.strftime("%Y%m%d%H")), int(pack.get("version", 0)))
    name = f"malwarebazaar-{version}.bin"
    shutil.copyfile(hashes_path, os.path.join(out_dir, name))
    pack["version"] = version
    pack["published"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    pack["expires"] = (now + datetime.timedelta(days=EXPIRY_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(trusted_path, "rb") as f:
        trusted = f.read()
    if len(trusted) % 32:
        sys.exit("trusted list length is not a multiple of 32")
    sets = []
    if trusted:
        tname = f"trusted-{version}.bin"
        shutil.copyfile(trusted_path, os.path.join(out_dir, tname))
        sets.append(
            {
                "file": tname,
                "sha256": hashlib.sha256(trusted).hexdigest(),
                "count": len(trusted) // 32,
                "family": "Mã độc phổ biến đã xác nhận",
                "severity": "malware",
                "trusted": True,
                "source": "abuse.ch MalwareBazaar, corroborated",
            }
        )
    sets.append(
        {
            "file": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "count": len(data) // 32,
            "family": "Mã độc đã biết",
            "severity": "suspicious",
            "source": "abuse.ch MalwareBazaar",
        }
    )
    pack["hash_sets"] = sets
    if yara_path:
        with open(yara_path, encoding="utf-8") as f:
            y = json.load(f)
        with open(os.path.join(out_dir, y["file"]), "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != y["sha256"]:
                sys.exit("YARA file does not match yara.json")
        pack["yara"] = {k: y[k] for k in ("file", "sha256", "rules", "source", "forge_tag", "rl_commit", "malware")}
    with open(os.path.join(out_dir, "pack.json"), "w", encoding="utf-8") as f:
        json.dump(pack, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(version)


if __name__ == "__main__":
    main()
