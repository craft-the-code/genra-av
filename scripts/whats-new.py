#!/usr/bin/env python3
"""User-facing "Có gì mới" notes for one version, one file per language. Standard library only.

Usage: whats-new.py <version>            print {"vi": "...", "en": "...", ...} (the updater's notes)
       whats-new.py --check <version>    only check the files and the writing rules
       whats-new.py --markdown <version> print every language as Markdown (GitHub release body)

Reads every whats-new/<version>.<lang>.md; Vietnamese and English are required (REQUIRED), any other
language code is picked up when its file exists. Each file is a one-sentence summary
line, a blank line, then 1 to 6 "- " bullets (docs/whats-new.md has the writing rules). It fails
when a file is missing, the shape is wrong, or the text looks technical: code, paths, file names,
links or developer words belong in CHANGELOG.md, not in what users read.
"""
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "whats-new")
REQUIRED = ("vi", "en")
# Heading per language in the GitHub release body; a language without one uses its code.
TITLES = {"vi": "Có gì mới", "en": "What's new"}
MAX_BULLETS = 6
MAX_CHARS = 160
# Signs that a line was written for developers rather than for users.
TECHNICAL = [
    (r"`", "backticks (code)"),
    (r"https?://", "a link"),
    (r"[A-Za-z0-9_]+\.(rs|ts|js|json|yml|yaml|py|toml|exe|msi|dmg|dll|md)\b", "a file name"),
    (r"(^|\s)[~/\\][\w.-]+[/\\]", "a path"),
    (r"::|\(\)|=>|->", "code"),
    (r"\b(API|SDK|CI|PR|commit|refactor|regex|struct|enum|clippy|Tauri|Rust|PowerShell|"
     r"stdout|stderr|null|undefined|SHA-?256|OLE2|OOXML|VBA|BIFF|hash)\b", "a developer word"),
]


def load(version: str, lang: str) -> tuple[str, list[str]]:
    path = os.path.join(ROOT, f"{version}.{lang}.md")
    if not os.path.exists(path):
        raise SystemExit(f"missing {os.path.relpath(path)}: every release needs user notes in {', '.join(REQUIRED)}")
    lines = [l.rstrip() for l in open(path, encoding="utf-8").read().strip().splitlines()]
    if not lines or lines[0].startswith("-"):
        raise SystemExit(f"{path}: start with a one-sentence summary, then the bullets")
    summary, bullets = lines[0].strip(), []
    for l in lines[1:]:
        if not l.strip():
            continue
        if l.startswith("- "):
            bullets.append(l[2:].strip())
        elif l.startswith("  ") and bullets:
            bullets[-1] += " " + l.strip()
        else:
            raise SystemExit(f"{path}: only a summary line and '- ' bullets, got: {l!r}")
    if not 1 <= len(bullets) <= MAX_BULLETS:
        raise SystemExit(f"{path}: {len(bullets)} bullets; write 1 to {MAX_BULLETS}, the ones a user notices")
    for text in [summary, *bullets]:
        if len(text) > MAX_CHARS:
            raise SystemExit(f"{path}: keep each line under {MAX_CHARS} characters: {text!r}")
        for pattern, what in TECHNICAL:
            if re.search(pattern, text, re.IGNORECASE if "developer" in what else 0):
                raise SystemExit(f"{path}: looks technical ({what}); say what changes for the user: {text!r}")
    return summary, bullets


def as_text(summary: str, bullets: list[str]) -> str:
    return summary + "\n\n" + "\n".join(f"- {b}" for b in bullets)


def main() -> None:
    args = sys.argv[1:]
    mode = args.pop(0) if args and args[0].startswith("--") else ""
    if len(args) != 1:
        raise SystemExit(__doc__)
    version = args[0]
    found = sorted(
        m.group(1)
        for f in os.listdir(ROOT)
        if (m := re.fullmatch(re.escape(version) + r"\.([a-z]{2,3}(?:-[A-Za-z]{2,4})?)\.md", f))
    )
    langs = list(REQUIRED) + [l for l in found if l not in REQUIRED]
    notes = {lang: load(version, lang) for lang in langs}
    if mode == "--check":
        return
    if mode == "--markdown":
        for lang, (summary, bullets) in notes.items():
            print(f"## {TITLES.get(lang, lang)}\n\n{as_text(summary, bullets)}\n")
        return
    print(json.dumps({lang: as_text(*v) for lang, v in notes.items()}, ensure_ascii=False))


if __name__ == "__main__":
    main()
