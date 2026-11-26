#!/usr/bin/env python3
"""Set the app version everywhere it is written. Standard library only.

Usage: bump-version.py <x.y.z>

Updates Cargo.toml ([workspace.package]), the workspace crates in Cargo.lock,
app/src-tauri/tauri.conf.json, app/package.json and app/package-lock.json. JSON key order and
the rest of each file are kept. Plain x.y.z only: the MSI installer accepts numeric versions only,
so pre-release suffixes are refused. Prints what changed; then run check-version.py v<x.y.z>.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import release_version as rv  # noqa: E402


def main() -> None:
    if len(sys.argv) != 2 or not rv.SEMVER.match(sys.argv[1]):
        raise SystemExit("usage: bump-version.py <x.y.z>  (numbers only, no 'v', no suffix)")
    version = sys.argv[1]
    before = rv.current_versions()

    rv.write(rv.CARGO_TOML, rv.set_cargo_workspace_version(rv.read(rv.CARGO_TOML), version))
    rv.write(rv.CARGO_LOCK, rv.set_lock_versions(rv.read(rv.CARGO_LOCK), rv.workspace_crates(), version))

    for path in (rv.TAURI_CONF, rv.PACKAGE_JSON):
        data = rv.load_json(path)
        if "version" not in data:
            raise SystemExit(f"{path} has no version")
        data["version"] = version
        rv.dump_json(path, data)

    lock = rv.load_json(rv.PACKAGE_LOCK)
    if "version" not in lock or "" not in lock.get("packages", {}):
        raise SystemExit("app/package-lock.json has no version")
    lock["version"] = version
    lock["packages"][""]["version"] = version
    rv.dump_json(rv.PACKAGE_LOCK, lock)

    after = rv.current_versions()
    for label, old in before.items():
        print(f"{label}: {old} -> {after[label]}")
    bad = {k: v for k, v in after.items() if v != version}
    if bad:
        raise SystemExit(f"not updated: {bad}")


if __name__ == "__main__":
    main()
