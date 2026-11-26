#!/usr/bin/env python3
"""Print the CHANGELOG.md section of one version, for the GitHub Release body. Standard library only.

Usage: release-notes.py <CHANGELOG.md> <x.y.z>

The section starts at a heading `## [x.y.z]` (anything may follow, e.g. ` - 2026-12-01`) and ends
at the next `## ` heading or at the link definitions at the end of the file. Fails if the section
is missing or empty, so a release is never published without notes.
"""
import re
import sys


def extract(text: str, version: str) -> str:
    heading = re.compile(r"^## \[" + re.escape(version) + r"\](?:\s.*)?$")
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if heading.match(line)), None)
    if start is None:
        raise SystemExit(f"CHANGELOG has no '## [{version}]' section (rename [Unreleased] first)")
    body = []
    for line in lines[start + 1:]:
        if line.startswith("## ") or re.match(r"^\[[^\]]+\]:\s", line):
            break
        body.append(line)
    notes = "\n".join(body).strip()
    if not notes:
        raise SystemExit(f"CHANGELOG section [{version}] is empty")
    return notes


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: release-notes.py <CHANGELOG.md> <x.y.z>")
    with open(sys.argv[1], encoding="utf-8") as f:
        print(extract(f.read(), sys.argv[2]))


if __name__ == "__main__":
    main()
