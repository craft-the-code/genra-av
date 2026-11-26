#!/usr/bin/env python3
"""Write the Tauri updater manifest (latest.json) for a release. Standard library only.

Usage: latest-json.py --dir <release-files> --version <x.y.z> --tag <tag> --repo <owner/name>
                      --notes-file <notes.md>

Reads the `<file>.sig` signatures that collect-bundles.py copied next to the versioned updater
files and writes <dir>/latest.json with URLs on this tag's release (the files of a published
release never change, unlike the fixed `latest/download` names). Platform keys follow the Tauri 2
updater: `<os>-<arch>` for the default installer and `<os>-<arch>-<bundle>` per bundle type.
With no signature at all (no updater key configured) it writes nothing and says so. With some but
not all three OSes signed it fails: a partial manifest would strand users of the missing OS.
"""
import argparse
import datetime
import json
import os
import re

# suffix of the signed file -> (os, bundle type, is the default for "<os>-<arch>")
KINDS = [
    (r"-setup\.exe", "windows", "nsis", True),
    (r"\.msi", "windows", "msi", False),
    (r"\.app\.tar\.gz", "darwin", "app", True),
    (r"\.AppImage", "linux", "appimage", True),
    (r"\.deb", "linux", "deb", False),
]
ARCH = {"x64": ["x86_64"], "amd64": ["x86_64"], "x86_64": ["x86_64"], "aarch64": ["aarch64"],
        "arm64": ["aarch64"], "universal": ["aarch64", "x86_64"]}


def main() -> None:
    ap = argparse.ArgumentParser()
    for opt in ("--dir", "--version", "--tag", "--repo", "--notes-file"):
        ap.add_argument(opt, required=True)
    args = ap.parse_args()
    v = re.escape(args.version)
    base = f"https://github.com/{args.repo}/releases/download/{args.tag}"

    platforms = {}
    for sig in sorted(f for f in os.listdir(args.dir) if f.endswith(".sig")):
        target = sig[: -len(".sig")]
        if not os.path.exists(os.path.join(args.dir, target)):
            raise SystemExit(f"{sig} has no {target}")
        for suffix, osname, bundle, default in KINDS:
            m = re.match(r"^[Gg]enra-(?:AV|av)_" + v + r"_([A-Za-z0-9]+)(?:_[A-Za-z-]+)?" + suffix + "$", target)
            if m:
                break
        else:
            raise SystemExit(f"unexpected signature file {sig}")
        archs = ARCH.get(m.group(1))
        if not archs:
            raise SystemExit(f"unknown arch in {target}")
        with open(os.path.join(args.dir, sig), encoding="utf-8") as f:
            entry = {"signature": f.read().strip(), "url": f"{base}/{target}"}
        for arch in archs:
            keys = [f"{osname}-{arch}-{bundle}"] + ([f"{osname}-{arch}"] if default else [])
            for key in keys:
                if key in platforms:
                    raise SystemExit(f"two files for {key}")
                platforms[key] = entry

    if not platforms:
        print("no updater signatures: latest.json skipped (TAURI_SIGNING_PRIVATE_KEY not set)")
        return
    missing = [k for k in ("windows-x86_64", "darwin-aarch64", "darwin-x86_64", "linux-x86_64") if k not in platforms]
    if missing:
        raise SystemExit(f"updater signatures missing for {missing}")

    with open(args.notes_file, encoding="utf-8") as f:
        notes = f.read().strip()
    manifest = {
        "version": args.version,
        "notes": notes,
        "pub_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platforms": dict(sorted(platforms.items())),
    }
    with open(os.path.join(args.dir, "latest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("latest.json: " + ", ".join(manifest["platforms"]))


if __name__ == "__main__":
    main()
