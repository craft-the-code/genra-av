#!/usr/bin/env python3
"""Pick the YARA rules Genra may ship, and assemble the pack's rule file (ADR 0004, layer 2).

Standard library only: the signing job runs this too, on sources it downloads itself, and
compares the result with what the build job produced (so the build job, which runs cargo, can
only *remove* rules: those Genra's engine refuses).

  yara_select.py select <sources.json> <disabled.json> <out-blocks.yar> --forge <core.yar> [--forge-tag T] [--rl <dir> --rl-commit C]
      Rules whose licence is on the allow list in sources.json, minus disabled.json, as blocks
      separated by `// @genra-rule` (imports before the first), for `genra-av yara check`.
  yara_select.py assemble <blocks.yar> <refused.txt> <malware.json> <licences-dir> <out-dir>
      Drops the refused rules (refusing outright when a kept rule uses one), and writes
      <out-dir>/yara-<sha12>.yar with the sources' licence texts at the top. Prints the pack's
      `yara` object as JSON: file, sha256, rules, source, forge_tag, rl_commit, malware.
  yara_select.py count <file.yar>
      Number of `rule` declarations (the same count the client checks).

Rules are copied as they are: author, reference and licence meta stay with each rule, and the
file starts with each source's licence and copyright notice (rules/licenses/), which is what the
Detection Rule License, BSD, MIT and Apache licences ask for. Comments between rules (YARA
Forge's per-repository headers) are dropped so no text lands under another source's rule.
Every YARA finding is `suspicious` (one press to quarantine) unless the rule is named in
rules/yara-malware.json, reviewed here; rule text never decides it.
"""
import hashlib
import json
import os
import re
import sys

MARK = "// @genra-rule"
RULE_LINE = re.compile(r"^(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z0-9_]+)", re.ASCII)
IMPORT = re.compile(r'^import\s+"([a-z0-9_]+)"\s*$')
# Modules Genra's engine (boreal with the "object" and "hash" features) provides.
MODULES = {"pe", "elf", "macho", "dotnet", "hash", "math", "string", "time", "dex"}


def fail(msg: str) -> None:
    sys.exit(f"yara_select: {msg}")


# Anything that looks like the start of a declaration. A line that matches this but not RULE_LINE
# (odd spacing, control characters) could be counted differently by another reader, so the
# rule holding it is left out.
LOOSE = re.compile(r"^\s*(?:private|global|rule)(?![A-Za-z0-9_])", re.ASCII)


def split_rules(text: str) -> tuple[set[str], list[tuple[str, str]]]:
    """(imports, [(rule name, block text)]) of a rule file. A block runs from its `rule` line to
    the first `}` alone at the start of a line; what follows until the next rule (comments,
    YARA Forge's repository headers) is dropped. A block holding an ambiguous declaration-like
    line is dropped."""
    imports: set[str] = set()
    blocks: list[tuple[str, list[str], bool]] = []
    open_block = False
    for line in text.splitlines():
        m = IMPORT.match(line.strip())
        if m and not open_block:
            imports.add(m.group(1))
            continue
        r = RULE_LINE.match(line)
        if r:
            blocks.append((r.group(1), [line], True))
            open_block = not line.rstrip().endswith("}") or line.count("{") > line.count("}")
            continue
        if not open_block or not blocks:
            continue
        name, lines, ok = blocks[-1]
        if LOOSE.match(line):
            ok = False
        lines.append(line)
        blocks[-1] = (name, lines, ok)
        if line.rstrip() == "}":
            open_block = False
    out = []
    for name, lines, ok in blocks:
        filled = [l for l in lines if l.strip()]
        # A rule whose last line is not its closing brace may have taken in the text after it.
        # A global rule would gate every other rule (and the build removing one would widen them).
        if ok and filled and filled[-1].rstrip().endswith("}") and not re.search(r"\bglobal\b", lines[0].split("rule", 1)[0]):
            out.append((name, "\n".join(lines).rstrip() + "\n"))
    return imports, out


def licence_of(block: str, sources: list[dict]) -> dict | None:
    # From the rule's own meta section only (before its strings and condition).
    meta = re.split(r"^\s*(?:strings|condition)\s*:", block, maxsplit=1, flags=re.M)[0]
    m = re.search(r'^\s*license_url\s*=\s*"([^"]*)"', meta, re.M)
    url = m.group(1) if m else ""
    for s in sources:
        if s.get("match") and url.startswith(s["match"]):
            return s
    return None


def select(args: list[str]) -> None:
    sources_path, disabled_path, out_path = args[0:3]
    opts = dict(zip(args[3::2], args[4::2]))
    sources = json.load(open(sources_path, encoding="utf-8"))
    disabled = set(json.load(open(disabled_path, encoding="utf-8")).get("rules", []))
    imports: set[str] = set()
    picked: list[tuple[str, str]] = []
    seen: set[str] = set()
    counts: dict[str, int] = {}

    excluded = [re.compile(p) for p in sources.get("exclude_names", [])]

    def take(name: str, block: str, src: str) -> None:
        if name in seen or name in disabled or any(p.search(name) for p in excluded):
            return
        seen.add(name)
        picked.append((name, block))
        counts[src] = counts.get(src, 0) + 1

    if "--forge" in opts:
        imp, rules = split_rules(open(opts["--forge"], encoding="utf-8", errors="strict").read())
        imports |= imp
        for name, block in rules:
            s = licence_of(block, sources["forge"])
            if s:
                take(name, block, s["name"])
    if "--rl" in opts:
        rl = sources["reversinglabs"]
        files = []
        for root, _, names in os.walk(opts["--rl"]):
            files += [os.path.join(root, n) for n in names if n.endswith((".yara", ".yar"))]
        for path in sorted(files, key=lambda p: os.path.relpath(p, opts["--rl"]).replace(os.sep, "/")):
            imp, rules = split_rules(open(path, encoding="utf-8", errors="strict").read())
            imports |= imp
            for name, block in rules:
                take(name, block, rl["name"])
    header = [f'import "{m}"' for m in sorted(imports & MODULES)]
    meta = {"forge_tag": opts.get("--forge-tag", ""), "rl_commit": opts.get("--rl-commit", ""), "counts": counts}
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"// genra-select {json.dumps(meta, sort_keys=True)}\n")
        f.write("\n".join(header) + "\n")
        for _, block in picked:
            f.write(f"\n{MARK}\n{block}")
    print(f"selected {len(picked)} rules: {json.dumps(counts, sort_keys=True)}", file=sys.stderr)


def count(text: str) -> int:
    return sum(1 for line in text.splitlines() if RULE_LINE.match(line))


def assemble(args: list[str]) -> None:
    blocks_path, refused_path, malware_path, licences_dir, out_dir = args[0:5]
    text = open(blocks_path, encoding="utf-8").read()
    refused = {l.strip() for l in open(refused_path, encoding="utf-8") if l.strip()}
    if any(not re.fullmatch(r"[A-Za-z0-9_]+", n) for n in refused):
        fail("odd name in the refused list")
    parts = text.split(f"\n{MARK}\n")
    head_lines = parts[0].splitlines()
    if not head_lines or not head_lines[0].startswith("// genra-select "):
        fail("not a selection file")
    meta = json.loads(head_lines[0][len("// genra-select ") :])
    imports = [l for l in head_lines[1:] if IMPORT.match(l)]
    names = lambda b: {m.group(1) for m in map(RULE_LINE.match, b.splitlines()) if m}
    kept = [b for b in parts[1:] if not (names(b) & refused)]
    # Removing a rule that a kept rule uses would leave a file no client can compile: the refused
    # list may only take out rules nothing else needs.
    if refused:
        used = re.compile(r"(?<![A-Za-z0-9_$])(" + "|".join(sorted(map(re.escape, refused))) + r")(?![A-Za-z0-9_])")
        for b in kept:
            body = "\n".join(l for l in b.splitlines() if not RULE_LINE.match(l))
            hit = used.search(body)
            if hit:
                fail(f"kept rule {sorted(names(b))[0]} uses the refused rule {hit.group(1)}")
    kept_names = set().union(*map(names, kept)) if kept else set()
    malware = sorted(set(json.load(open(malware_path, encoding="utf-8")).get("rules", [])) & kept_names)
    sources = ", ".join(f"{k} ({v})" for k, v in sorted(meta["counts"].items()))
    header = [
        "// Genra AV YARA rules, assembled by scripts/yara_select.py. Each rule keeps its author,",
        "// reference and licence meta. Sources and licences: docs/yara-rules.md.",
        f"// YARA Forge release {meta['forge_tag'] or '-'}; ReversingLabs commit {meta['rl_commit'] or '-'}.",
        f"// Rules by source: {sources}.",
        "// The licence and copyright notice of every source follows; each covers that source's rules.",
        "/*",
    ]
    seen_texts: dict[str, str] = {}
    for name in sorted(os.listdir(licences_dir)):
        if not name.endswith(".txt"):
            continue
        body = open(os.path.join(licences_dir, name), encoding="utf-8").read().replace("*/", "* /").strip()
        src = name[: -len(".txt")]
        if body in seen_texts:
            header.append(f"---- {src}: same licence text as {seen_texts[body]} above ----")
            continue
        seen_texts[body] = src
        header.append(f"---- {src} ----")
        header.extend(body.splitlines())
    header += ["*/", ""]
    body = "\n".join(header + imports) + "\n" + "".join("\n" + b for b in kept)
    if any(RULE_LINE.match(l) for l in "\n".join(header).splitlines()):
        fail("a licence text has a line that reads as a rule")
    data = body.encode("utf-8")
    sha = hashlib.sha256(data).hexdigest()
    name = f"yara-{sha[:12]}.yar"
    with open(os.path.join(out_dir, name), "wb") as f:
        f.write(data)
    print(json.dumps({
        "file": name,
        "sha256": sha,
        "rules": count(body),
        "source": f"YARA Forge core {meta['forge_tag']} + ReversingLabs (licensed sets only)",
        "forge_tag": meta["forge_tag"],
        "rl_commit": meta["rl_commit"],
        "malware": malware,
    }, sort_keys=True))


def main() -> None:
    if len(sys.argv) < 2:
        fail(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "select":
        select(args)
    elif cmd == "assemble":
        assemble(args)
    elif cmd == "count":
        print(count(open(args[0], encoding="utf-8").read()))
    else:
        fail(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
