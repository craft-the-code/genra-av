#!/usr/bin/env python3
"""Payload hashes from abuse.ch's other feeds, for the untrusted hash list (ADR 0004, layer 1).
Standard library only, like the other pack scripts.

MalwareBazaar stays the main feed and the only one graded into the trusted list (hash_grade.py
needs its family and vendor results). These two add hashes it may not have yet; every one of them
is only ever "suspicious":

  urlhaus <out.txt>     URLhaus payloads seen in the last 3 days (at most 1000), only those
                        URLhaus names a malware family for: a payload without one is often a
                        legitimate file served from a compromised site.
  threatfox <out.txt>   ThreatFox SHA-256 IOCs of the last 7 days with confidence >= MIN_CONFIDENCE.

ABUSECH_AUTH_KEY must be set (the same key as MalwareBazaar). Each command writes sorted, unique,
lower-case hex, one per line, and exits non-zero on a network or format error (the workflow treats
these feeds as optional).
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

URLHAUS = "https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/1000/"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
MIN_CONFIDENCE = 75
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def hex64(v) -> str | None:
    s = (v or "").strip().lower() if isinstance(v, str) else ""
    return s if HEX64.match(s) else None


def urlhaus_hashes(body: dict) -> set[str]:
    """SHA-256 of payloads with a named family. `no_results` is an empty answer, not an error."""
    status = body.get("query_status")
    if status == "no_results":
        return set()
    if status != "ok" or not isinstance(body.get("payloads"), list):
        raise ValueError(f"URLhaus answered {status!r}")
    out = set()
    for p in body["payloads"]:
        if not isinstance(p, dict) or not (p.get("signature") or "").strip():
            continue
        h = hex64(p.get("sha256_hash"))
        if h:
            out.add(h)
    return out


def threatfox_hashes(body: dict) -> set[str]:
    """SHA-256 IOCs at or above MIN_CONFIDENCE. `no_result` is an empty answer."""
    status = body.get("query_status")
    if status in ("no_result", "no_results"):
        return set()
    if status != "ok" or not isinstance(body.get("data"), list):
        raise ValueError(f"ThreatFox answered {status!r}")
    out = set()
    for i in body["data"]:
        if not isinstance(i, dict) or i.get("ioc_type") != "sha256_hash":
            continue
        try:
            conf = int(i.get("confidence_level") or 0)
        except (TypeError, ValueError):
            continue
        h = hex64(i.get("ioc"))
        if h and conf >= MIN_CONFIDENCE:
            out.add(h)
    return out


def fetch(url: str, data: bytes | None = None) -> dict:
    key = os.environ.get("ABUSECH_AUTH_KEY", "")
    if not key:
        sys.exit("ABUSECH_AUTH_KEY is not set")
    headers = {"Auth-Key": key, "User-Agent": "genra-av-ci"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:
                time.sleep(min(int(e.headers.get("Retry-After") or 60), 300))
                continue
            raise
    raise RuntimeError("unreachable")


def write(path: str, hashes: set[str]) -> None:
    with open(path, "w", encoding="ascii") as f:
        for h in sorted(hashes):
            f.write(h + "\n")
    print(f"{len(hashes)} hashes -> {path}")


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in ("urlhaus", "threatfox"):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "urlhaus":
        hashes = urlhaus_hashes(fetch(URLHAUS))
    else:
        hashes = threatfox_hashes(fetch(THREATFOX, json.dumps({"query": "get_iocs", "days": 7}).encode()))
    write(argv[2], hashes)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
