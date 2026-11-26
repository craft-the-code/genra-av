"""Where the app version lives, shared by bump-version.py and check-version.py. Standard library only.

The version is written in five places that must agree:
- Cargo.toml `[workspace.package] version` (every crate uses `version.workspace = true`);
- Cargo.lock, the entries of the workspace crates;
- app/src-tauri/tauri.conf.json `version` (installers and the updater read this one);
- app/package.json and app/package-lock.json (`version` and `packages[""].version`).
"""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")

CARGO_TOML = os.path.join(ROOT, "Cargo.toml")
CARGO_LOCK = os.path.join(ROOT, "Cargo.lock")
TAURI_CONF = os.path.join(ROOT, "app", "src-tauri", "tauri.conf.json")
PACKAGE_JSON = os.path.join(ROOT, "app", "package.json")
PACKAGE_LOCK = os.path.join(ROOT, "app", "package-lock.json")

_SECTION = re.compile(r"^\[workspace\.package\][^\[]*", re.M)
_VERSION_LINE = re.compile(r'^(version\s*=\s*")([^"]*)(")', re.M)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def load_json(path):
    return json.loads(read(path))


def dump_json(path, data):
    # json keeps insertion order, so keys stay where they were; the repo files use indent 2.
    write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def cargo_workspace_version(text):
    section = _SECTION.search(text)
    if not section:
        raise SystemExit("Cargo.toml has no [workspace.package] section")
    line = _VERSION_LINE.search(section.group(0))
    if not line:
        raise SystemExit("Cargo.toml [workspace.package] has no version")
    return line.group(2)


def set_cargo_workspace_version(text, version):
    section = _SECTION.search(text)
    if not section:
        raise SystemExit("Cargo.toml has no [workspace.package] section")
    new_section, n = _VERSION_LINE.subn(lambda m: m.group(1) + version + m.group(3), section.group(0), count=1)
    if n != 1:
        raise SystemExit("Cargo.toml [workspace.package] has no version")
    return text[: section.start()] + new_section + text[section.end():]


def workspace_crates():
    """Names of the workspace member crates, from each member's Cargo.toml."""
    members = re.search(r"^members\s*=\s*\[([^\]]*)\]", read(CARGO_TOML), re.M)
    if not members:
        raise SystemExit("Cargo.toml has no workspace members")
    names = []
    for member in re.findall(r'"([^"]+)"', members.group(1)):
        manifest = read(os.path.join(ROOT, member, "Cargo.toml"))
        package = re.search(r"^\[package\][^\[]*", manifest, re.M)
        name = package and re.search(r'^name\s*=\s*"([^"]+)"', package.group(0), re.M)
        if not name:
            raise SystemExit(f"{member}/Cargo.toml has no package name")
        names.append(name.group(1))
    return names


def _lock_entry(name):
    return re.compile(r'(\[\[package\]\]\nname = "' + re.escape(name) + r'"\nversion = ")([^"]*)(")')


def lock_versions(text, names):
    found = {}
    for name in names:
        m = _lock_entry(name).search(text)
        found[name] = m.group(2) if m else None
    return found


def set_lock_versions(text, names, version):
    for name in names:
        text, n = _lock_entry(name).subn(lambda m: m.group(1) + version + m.group(3), text, count=1)
        if n != 1:
            raise SystemExit(f"Cargo.lock has no entry for {name}")
    return text


def current_versions():
    """Every place the version is written, as {label: version}."""
    versions = {"Cargo.toml [workspace.package]": cargo_workspace_version(read(CARGO_TOML))}
    for name, v in lock_versions(read(CARGO_LOCK), workspace_crates()).items():
        versions[f"Cargo.lock {name}"] = v
    versions["app/src-tauri/tauri.conf.json"] = load_json(TAURI_CONF).get("version")
    versions["app/package.json"] = load_json(PACKAGE_JSON).get("version")
    lock = load_json(PACKAGE_LOCK)
    versions["app/package-lock.json"] = lock.get("version")
    versions['app/package-lock.json packages[""]'] = lock.get("packages", {}).get("", {}).get("version")
    return versions
