#!/usr/bin/env python3
"""Copy the Tauri bundles of one OS to the release file names. Standard library only.

Usage: collect-bundles.py --os windows|macos|linux --version <x.y.z> --bundle-dir <dir> --out <dir>
                          [--expect-updater]

<bundle-dir> is Tauri's `target/<triple>/release/bundle`. Each installer is copied twice:
- a fixed name, so `releases/latest/download/<name>` links never change
  (Genra-AV-Setup.exe, Genra-AV.msi, Genra-AV.dmg, Genra-AV.AppImage, genra-av.deb);
- a versioned name without spaces (GitHub would rename spaces to dots), e.g.
  Genra-AV_0.1.0_universal.dmg, genra-av_0.1.0_amd64.deb.
Updater files (the macOS .app.tar.gz and every `<installer>.sig`) are copied under the versioned
name only; latest.json points at those. With --expect-updater a missing signature of the NSIS
installer, the .app tarball or the AppImage is an error; signatures found are always copied.
"""
import argparse
import glob
import os
import re
import shutil

# (bundle subfolder, pattern, fixed name, updater signature required with --expect-updater).
# The .msi and .deb signatures are copied when Tauri writes them, but only the default updater
# bundle of each OS (NSIS, the .app tarball, AppImage) must be signed.
INSTALLERS = {
    "windows": [("nsis", "*-setup.exe", "Genra-AV-Setup.exe", True), ("msi", "*.msi", "Genra-AV.msi", False)],
    "macos": [("dmg", "*.dmg", "Genra-AV.dmg", True)],
    "linux": [("appimage", "*.AppImage", "Genra-AV.AppImage", True), ("deb", "*.deb", "genra-av.deb", False)],
}


def versioned(name: str) -> str:
    out = re.sub(r"\s+", "-", name)
    return out.lower() if out.endswith(".deb") else out


def only(pattern: str) -> str:
    found = sorted(glob.glob(pattern))
    if len(found) != 1:
        raise SystemExit(f"expected exactly one {pattern}, found {found}")
    return found[0]


def copy(src: str, out: str, name: str) -> None:
    dst = os.path.join(out, name)
    if os.path.exists(dst):
        raise SystemExit(f"{name} written twice")
    shutil.copyfile(src, dst)
    print(f"{os.path.basename(src)} -> {name} ({os.path.getsize(dst)} bytes)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--os", required=True, choices=sorted(INSTALLERS))
    ap.add_argument("--version", required=True)
    ap.add_argument("--bundle-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--expect-updater", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    v = re.escape(args.version)

    for sub, pattern, fixed, required in INSTALLERS[args.os]:
        src = only(os.path.join(glob.escape(args.bundle_dir), sub, pattern))
        name = versioned(os.path.basename(src))
        if not re.search(r"_" + v + r"_", name):
            raise SystemExit(f"{name} does not carry version {args.version}")
        copy(src, args.out, fixed)
        copy(src, args.out, name)
        if args.os == "macos":
            # The updater takes the .app as a tarball; Tauri names it without version or arch.
            arch = re.search(r"_" + v + r"_([^.]+)\.dmg$", name).group(1)
            tars = glob.glob(os.path.join(glob.escape(args.bundle_dir), "macos", "*.app.tar.gz"))
            if len(tars) > 1:
                raise SystemExit(f"several updater tarballs: {tars}")
            if not tars:
                if args.expect_updater:
                    raise SystemExit("no updater tarball (macos/*.app.tar.gz)")
                continue
            src, name = tars[0], f"Genra-AV_{args.version}_{arch}.app.tar.gz"
            copy(src, args.out, name)
        sig = src + ".sig"
        if os.path.exists(sig):
            copy(sig, args.out, name + ".sig")
        elif args.expect_updater and required:
            raise SystemExit(f"no updater signature for {os.path.basename(src)}")


if __name__ == "__main__":
    main()
