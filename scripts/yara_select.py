#!/usr/bin/env python3
"""Pick the YARA rules Genra may ship, and assemble the pack's rule file (ADR 0004, layer 2).

Standard library only: the signing job runs this too, on sources it downloads itself, and
compares the result with what the build job produced (so the build job, which runs cargo, can
only *remove* rules: those Genra's engine refuses).

  yara_select.py select <sources.json> <disabled.json> <out-blocks.yar> --forge <core.yar> [--forge-tag T] [--rl <dir> --rl-commit C]
      Rules whose licence is on the allow list in sources.json, minus disabled.json, as blocks
      separated by `// @genra-rule` (imports before the first), for `genra-av yara check`.
  yara_select.py assemble <blocks.yar> <refused.txt> <out-dir>
      Drops the refused rules and writes <out-dir>/yara-<sha12>.yar with the attribution header.
      Prints {"file", "sha256", "rules", "source"} as JSON.
  yara_select.py count <file.yar>
      Number of `rule` declarations (the same count the client checks).

Rules are copied as they are: author, reference and licence meta stay with each rule, which is
what the Detection Rule License (signature-base, SEKOIA) and the BSD licences ask for. Every
YARA finding is `suspicious` (one press to quarantine) unless a rule carries
`genra_severity = "malware"`, which this script never writes yet.
"""
import hashlib
import json
import os
import re
import sys

MARK = "// @genra-rule"
RULE_LINE = re.compile(r"^(?:(?:private|global)\s+)*rule\s+([A-Za-z0-9_]+)\b")
IMPORT = re.compile(r'^import\s+"([a-z0-9_]+)"\s*$')
# Modules Genra's engine (boreal with the "object" and "hash" features) provides.
MODULES = {"pe", "elf", "macho", "dotnet", "hash", "math", "string", "time", "dex"}


def fail(msg: str) -> None:
    sys.exit(f"yara_select: {msg}")


def split_rules(text: str) -> tuple[set[str], list[tuple[str, str]]]:
    """(imports, [(rule name, block text)]) of a rule file. Comments and blank lines before a
    rule belong to the block before it, which is harmless."""
    imports: set[str] = set()
    blocks: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        m = IMPORT.match(line.strip())
        if m:
            imports.add(m.group(1))
            continue
        r = RULE_LINE.match(line)
        if r:
            blocks.append((r.group(1), [line]))
        elif blocks:
            blocks[-1][1].append(line)
    return imports, [(n, "\n".join(b).rstrip() + "\n") for n, b in blocks]


def licence_of(block: str, sources: list[dict]) -> dict | None:
    m = re.search(r'^\s*license_url\s*=\s*"([^"]*)"', block, re.M)
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

    def take(name: str, block: str, src: str) -> None:
        if name in seen or name in disabled:
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
        for path in sorted(files, key=lambda p: os.path.relpath(p, opts["--rl"])):
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
    blocks_path, refused_path, out_dir = args[0:3]
    text = open(blocks_path, encoding="utf-8").read()
    refused = {l.strip() for l in open(refused_path, encoding="utf-8") if l.strip()}
    parts = text.split(f"\n{MARK}\n")
    head_lines = parts[0].splitlines()
    if not head_lines or not head_lines[0].startswith("// genra-select "):
        fail("not a selection file")
    meta = json.loads(head_lines[0][len("// genra-select ") :])
    imports = [l for l in head_lines[1:] if IMPORT.match(l)]
    kept = [b for b in parts[1:] if not ({m.group(1) for m in map(RULE_LINE.match, b.splitlines()) if m} & refused)]
    sources = ", ".join(f"{k} ({v})" for k, v in sorted(meta["counts"].items()))
    header = [
        "// Genra AV YARA rules, assembled by scripts/yara_select.py. Each rule keeps its author,",
        "// reference and licence meta. Sources and licences: docs/yara-rules.md.",
        f"// YARA Forge release {meta['forge_tag'] or '-'}; ReversingLabs commit {meta['rl_commit'] or '-'}.",
        f"// Rules by source: {sources}.",
        "// signature-base and SEKOIA rules: Detection Rule License 1.1, https://github.com/Neo23x0/signature-base/blob/master/LICENSE",
        "",
    ]
    body = "\n".join(header + imports) + "\n" + "".join("\n" + b for b in kept)
    data = body.encode("utf-8")
    sha = hashlib.sha256(data).hexdigest()
    name = f"yara-{sha[:12]}.yar"
    with open(os.path.join(out_dir, name), "wb") as f:
        f.write(data)
    print(json.dumps({"file": name, "sha256": sha, "rules": count(body), "source": f"YARA Forge core {meta['forge_tag']} + ReversingLabs (licensed sets only)"}))


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
