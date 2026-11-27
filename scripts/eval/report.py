#!/usr/bin/env python3
"""Turn `genra-av scan --json` output into the detection report. Standard library only.

Usage: report.py --malware <scan.jsonl> --manifest <manifest.json> [--clean <scan.jsonl> ...] [--json out.json]

Malware results are grouped by the folder each sample sat in (its MalwareBazaar file type). For each
type it reports how many were caught at all, and how many were caught *without* the hash lists (rules
and built-in checks only): the hash lists contain MalwareBazaar's own recent samples, so the first
number flatters us and the second says what we catch in files nobody has listed yet.

A third number is what the YARA family rules alone catch (rule ids `yara.*`), so each layer's
share is visible (ADR 0004, "measurement gates every layer"). On a run with `scan --defender`
(Windows), Defender's findings (`defender.*`) are left out of every column but the last, which
counts the samples Genra called only suspicious and Defender raised to malware.

Clean results count false positives: any file rated suspicious or malware, listed by rule; the
YARA rules among them are listed once more by name, ready for rules/yara-disabled.json.
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

    manifest = json.load(open(a.manifest))
    family = {m["sha256"]: m["family"] for m in manifest}
    # Denominators come from what was downloaded, not from what got scanned: a sample that failed
    # to unpack or was too large to read counts as "not scanned", never silently disappears.
    fetched = collections.Counter(m["type"] for m in manifest)
    by_type = collections.defaultdict(lambda: {"n": 0, "scanned": 0, "any": 0, "no_hash": 0, "yara": 0, "malware": 0, "defender": 0})
    for t, n in fetched.items():
        by_type[t]["n"] = n
    missed_families = collections.Counter()
    asked_defender = False
    for r in rows(a.malware):
        # The CLI on Windows writes backslashes; this script may run elsewhere.
        t = os.path.basename(os.path.dirname(r["path"].replace("\\", "/"))) or "?"
        s = by_type[t]
        s["scanned"] += 1
        everything = [f for f in r.get("findings", []) if serious(f)]
        is_defender = lambda f: f["rule"].startswith("defender.")
        asked_defender |= any(f["rule"].startswith("defender.") for f in r.get("findings", []))
        found = [f for f in everything if not is_defender(f)]
        if not any(f.get("severity") == "malware" for f in found) and any(is_defender(f) and f.get("severity") == "malware" for f in everything):
            s["defender"] += 1
        if found:
            s["any"] += 1
        if any(not f["rule"].startswith("hash.") for f in found):
            s["no_hash"] += 1
        if any(f["rule"].startswith("yara.") for f in found):
            s["yara"] += 1
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
    total = {k: sum(s[k] for s in by_type.values()) for k in ("n", "scanned", "any", "no_hash", "yara", "malware", "defender")}
    print("## Genra AV detection report\n")
    print("Percentages are of samples downloaded. Archive types (zip, rar, 7z, iso) read near 0 % without")
    print("hash lists until archive scanning lands (ADR 0004 step 2); that is expected, not a regression.\n")
    extra = " Raised to malware by Defender |" if asked_defender else ""
    print("| File type | Samples | Not scanned | Caught | Caught without hash lists | By YARA rules | Rated malware |" + extra)
    print("|---|---:|---:|---:|---:|---:|---:|" + ("---:|" if asked_defender else ""))
    for t in sorted(by_type):
        s = by_type[t]
        d = f" {pct(s['defender'], s['n'])} |" if asked_defender else ""
        print(f"| {t} | {s['n']} | {s['n'] - s['scanned']} | {pct(s['any'], s['n'])} | {pct(s['no_hash'], s['n'])} | {pct(s['yara'], s['n'])} | {pct(s['malware'], s['n'])} |{d}")
    d = f" **{pct(total['defender'], total['n'])}** |" if asked_defender else ""
    print(f"| **all** | **{total['n']}** | **{total['n'] - total['scanned']}** | **{pct(total['any'], total['n'])}** | **{pct(total['no_hash'], total['n'])}** | **{pct(total['yara'], total['n'])}** | **{pct(total['malware'], total['n'])}** |{d}")
    if asked_defender:
        print("\nWindows Defender was asked about the samples Genra called suspicious; every other column is Genra alone.")
    print(f"\nClean files scanned: {clean_n}; false positives: **{len(fp)}**.")
    for p, rules in fp[:50]:
        print(f"- `{p}`: {', '.join(rules)}")
    yara_fp = collections.Counter(r.split("@")[0][len("yara."):] for _, rules in fp for r in rules if r.startswith("yara."))
    if yara_fp:
        print("\nYARA rules that matched clean files (add to rules/yara-disabled.json):")
        for name, n in yara_fp.most_common():
            print(f"- `{name}` ({n})")
    if missed_families:
        print("\nMost-missed families:", ", ".join(f"{k} ({v})" for k, v in missed_families.most_common(10)))
    if a.json:
        json.dump({"by_type": by_type, "total": total, "defender": asked_defender, "clean": clean_n, "false_positives": len(fp), "yara_false_positive_rules": dict(yara_fp)}, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
