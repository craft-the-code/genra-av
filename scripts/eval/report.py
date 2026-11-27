#!/usr/bin/env python3
"""Turn `genra-av scan --json` output into the detection report. Standard library only.

Usage: report.py --malware <scan.jsonl> --manifest <manifest.json> [--clean <scan.jsonl> ...] [--json out.json]

Malware results are grouped by the folder each sample sat in (its MalwareBazaar file type). For each
type it reports how many were caught at all, and how many were caught *without* the hash lists (rules
and built-in checks only): the hash lists contain MalwareBazaar's own recent samples, so the first
number flatters us and the second says what we catch in files nobody has listed yet.

Clean results count false positives: any file rated suspicious or malware, listed by rule.
Prints Markdown (for the job summary); --json writes the numbers for later comparison.
"""
import argparse
import collections
import json
import os


def rows(path: str):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                yield json.loads(line)


def serious(f: dict) -> bool:
    return f.get("severity") in ("suspicious", "malware")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--malware", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--clean", action="append", default=[])
    ap.add_argument("--json")
    a = ap.parse_args()

    family = {m["sha256"]: m["family"] for m in json.load(open(a.manifest))}
    by_type = collections.defaultdict(lambda: {"n": 0, "any": 0, "no_hash": 0, "malware": 0})
    missed_families = collections.Counter()
    for r in rows(a.malware):
        t = os.path.basename(os.path.dirname(r["path"])) or "?"
        s = by_type[t]
        s["n"] += 1
        found = [f for f in r.get("findings", []) if serious(f)]
        if found:
            s["any"] += 1
        if any(not f["rule"].startswith("hash.") for f in found):
            s["no_hash"] += 1
        if any(f.get("severity") == "malware" for f in found):
            s["malware"] += 1
        if not found:
            missed_families[family.get(r.get("sha256", ""), "") or "(no family)"] += 1

    fp = []
    clean_n = 0
    for path in a.clean:
        for r in rows(path):
            clean_n += 1
            found = [f["rule"] for f in r.get("findings", []) if serious(f)]
            if found:
                fp.append((r["path"], found))

    pct = lambda x, n: f"{100 * x / n:.0f} %" if n else "–"
    total = {k: sum(s[k] for s in by_type.values()) for k in ("n", "any", "no_hash", "malware")}
    print("## Genra AV detection report\n")
    print("| File type | Samples | Caught | Caught without hash lists | Rated malware |")
    print("|---|---:|---:|---:|---:|")
    for t in sorted(by_type):
        s = by_type[t]
        print(f"| {t} | {s['n']} | {pct(s['any'], s['n'])} | {pct(s['no_hash'], s['n'])} | {pct(s['malware'], s['n'])} |")
    print(f"| **all** | **{total['n']}** | **{pct(total['any'], total['n'])}** | **{pct(total['no_hash'], total['n'])}** | **{pct(total['malware'], total['n'])}** |")
    print(f"\nClean files scanned: {clean_n}; false positives: **{len(fp)}**.")
    for p, rules in fp[:50]:
        print(f"- `{p}`: {', '.join(rules)}")
    if missed_families:
        print("\nMost-missed families:", ", ".join(f"{k} ({v})" for k, v in missed_families.most_common(10)))
    if a.json:
        json.dump({"by_type": by_type, "total": total, "clean": clean_n, "false_positives": len(fp)}, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
