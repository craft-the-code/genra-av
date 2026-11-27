#!/usr/bin/env python3
"""Grade MalwareBazaar hashes: which may quarantine without asking (ADR 0004, layer 1).
Standard library only: the signing job runs this too, and it runs no third-party code.

A hash is trusted when all of these hold:
- MalwareBazaar names a family on rules/families.json "families", and not one on "never_trusted";
- at least MIN_ENGINES independent analysis engines in the entry's vendor_intel call it malicious;
- MalwareBazaar first saw it at least MIN_AGE ago, and the entry still exists (not withdrawn).

Commands (ABUSECH_AUTH_KEY in the environment for the ones that ask MalwareBazaar):
  candidates <recent.csv> <families.json> <state.json>
      Add the export's hashes whose family is listed to the pending state (sha -> first_seen).
  promote <families.json> <state.json> <prev-trusted.txt> <trusted.txt>
      Ask MalwareBazaar about pending hashes old enough; write prev + newly qualified to
      trusted.txt (sorted hex), drop decided ones from the state. At most MAX_PER_RUN lookups.
  verify <families.json> <additions.txt>
      Signing job: re-check every hash added since the previous signed pack, independently of the
      build job. Exits non-zero if any fails, or if there are more than MAX_PER_RUN.
"""
import csv
import datetime
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://mb-api.abuse.ch/api/v1/"
MIN_ENGINES = 2
MIN_AGE = datetime.timedelta(hours=48)
MAX_PENDING_AGE = datetime.timedelta(days=14)
MAX_PER_RUN = 400
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def parse_time(s: str) -> datetime.datetime | None:
    try:
        return datetime.datetime.strptime(s.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    except (ValueError, AttributeError):
        return None


def load_families(path: str) -> tuple[set[str], set[str]]:
    d = json.load(open(path, encoding="utf-8"))
    low = lambda xs: {x.strip().lower() for x in xs}
    return low(d["families"]), low(d.get("never_trusted", []))


def family_ok(name: str, fams: tuple[set[str], set[str]]) -> bool:
    n = (name or "").strip().lower()
    return bool(n) and n in fams[0] and n not in fams[1]


# ---- MalwareBazaar ----

def get_info(sha: str) -> dict | None:
    key = os.environ.get("ABUSECH_AUTH_KEY", "")
    if not key:
        sys.exit("ABUSECH_AUTH_KEY is not set")
    data = urllib.parse.urlencode({"query": "get_info", "hash": sha}).encode()
    req = urllib.request.Request(API, data=data, headers={"Auth-Key": key, "User-Agent": "genra-av-ci"})
    for attempt in range(6):
        time.sleep(1.0)  # paced: MalwareBazaar answers 429 when asked too fast
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                body = json.loads(r.read())
            if body.get("query_status") != "ok" or not body.get("data"):
                return None
            return body["data"][0]
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(min(int(e.headers.get("Retry-After") or 60), 300))
            else:
                time.sleep(3 * (attempt + 1))
        except Exception:  # noqa: BLE001 - retried, then raised below
            time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"MalwareBazaar did not answer for {sha}")


def malicious_engines(vendor_intel: dict) -> list[str]:
    """Engines in vendor_intel that call the file malicious. Each vendor reports in its own shape,
    so this reads only clear verdict fields and numeric scores, and ignores everything else."""
    found = []
    for vendor, entry in (vendor_intel or {}).items():
        items = entry if isinstance(entry, list) else [entry]
        hit = False
        for it in items:
            if not isinstance(it, dict):
                continue
            for k in ("verdict", "status", "detection", "result"):
                v = it.get(k)
                if isinstance(v, str) and re.search(r"malic|malware", v, re.I) and not re.search(r"not|no |non|benign|clean", v, re.I):
                    hit = True
            for k, limit in (("score", 8.0), ("maliciousness", 70.0)):
                try:
                    if k in it and float(it[k]) >= (0.8 if vendor.upper().startswith("YOROI") and k == "score" else limit):
                        hit = True
                except (TypeError, ValueError):
                    pass
        if hit:
            found.append(vendor)
    return sorted(set(found))


def qualifies(info: dict | None, fams, now: datetime.datetime) -> tuple[bool, str]:
    if not info:
        return False, "not on MalwareBazaar (withdrawn or unknown)"
    if not family_ok(info.get("signature") or "", fams):
        return False, f"family {info.get('signature')!r} is not on the trusted list"
    seen = parse_time(info.get("first_seen") or "")
    if not seen or now - seen < MIN_AGE:
        return False, "listed less than 48 hours ago"
    engines = malicious_engines(info.get("vendor_intel") or {})
    if len(engines) < MIN_ENGINES:
        return False, f"only {len(engines)} engine(s) agree"
    return True, f"{info.get('signature')}: {', '.join(engines)}"


# ---- commands ----

def read_hex_lines(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    out = set()
    for line in open(path, encoding="utf-8"):
        h = line.strip().lower()
        if HEX64.match(h):
            out.add(h)
    return out


def recent_rows(text: str):
    """Rows of a MalwareBazaar CSV export as dicts, using the commented header line."""
    lines = text.splitlines()
    header = next((l.lstrip("#").strip() for l in lines if l.startswith("#") and "sha256_hash" in l), None)
    if not header:
        sys.exit("export has no header line naming sha256_hash")
    body = [l for l in lines if l and not l.startswith("#")]
    yield from csv.DictReader(io.StringIO(header + "\n" + "\n".join(body)), skipinitialspace=True)


def cmd_candidates(recent: str, families: str, state_path: str) -> None:
    fams = load_families(families)
    state = json.load(open(state_path)) if os.path.exists(state_path) else {}
    added = 0
    for row in recent_rows(open(recent, encoding="utf-8", errors="replace").read()):
        sha = (row.get("sha256_hash") or "").strip().strip('"').lower()
        if HEX64.match(sha) and sha not in state and family_ok((row.get("signature") or "").strip('" '), fams):
            state[sha] = (row.get("first_seen_utc") or "").strip('" ')
            added += 1
    json.dump(state, open(state_path, "w"), indent=0, sort_keys=True)
    print(f"candidates: +{added}, pending {len(state)}", file=sys.stderr)


def cmd_promote(families: str, state_path: str, prev_trusted: str, out: str) -> None:
    fams = load_families(families)
    now = utcnow()
    state = json.load(open(state_path)) if os.path.exists(state_path) else {}
    trusted = read_hex_lines(prev_trusted)
    asked = promoted = 0
    for sha, first in sorted(state.items(), key=lambda kv: kv[1]):
        seen = parse_time(first)
        if seen and now - seen > MAX_PENDING_AGE:
            del state[sha]  # never qualified in two weeks: it stays a suspicious feed hash
            continue
        if not seen or now - seen < MIN_AGE or sha in trusted or asked >= MAX_PER_RUN:
            continue
        asked += 1
        ok, why = qualifies(get_info(sha), fams, now)
        if ok:
            trusted.add(sha)
            promoted += 1
            del state[sha]
        elif "48 hours" not in why:
            del state[sha]
    with open(out, "w") as f:
        f.writelines(h + "\n" for h in sorted(trusted))
    json.dump(state, open(state_path, "w"), indent=0, sort_keys=True)
    print(f"promote: asked {asked}, promoted {promoted}, trusted {len(trusted)}, pending {len(state)}", file=sys.stderr)


def cmd_verify(families: str, additions: str) -> None:
    fams = load_families(families)
    now = utcnow()
    new = sorted(read_hex_lines(additions))
    if len(new) > MAX_PER_RUN:
        sys.exit(f"verify: {len(new)} additions is more than {MAX_PER_RUN} in one run")
    bad = []
    for sha in new:
        ok, why = qualifies(get_info(sha), fams, now)
        if not ok:
            bad.append(f"{sha}: {why}")
    if bad:
        sys.exit("verify: refused trusted additions:\n" + "\n".join(bad))
    print(f"verify: {len(new)} trusted additions confirmed with MalwareBazaar")


def main() -> None:
    cmd, args = (sys.argv[1], sys.argv[2:]) if len(sys.argv) > 1 else ("", [])
    table = {"candidates": (cmd_candidates, 3), "promote": (cmd_promote, 4), "verify": (cmd_verify, 2)}
    if cmd not in table or len(args) != table[cmd][1]:
        sys.exit(__doc__)
    table[cmd][0](*args)


if __name__ == "__main__":
    main()
