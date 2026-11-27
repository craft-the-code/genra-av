#!/usr/bin/env python3
"""SQL to load known-bad hashes into the backend's `known_bad` table (online lookup, ADR 0004 step 5).

  known-bad-sql.py <source> <hashes.txt> [more.txt …] > load.sql
  npx --prefix backend wrangler d1 execute genra --remote --file load.sql

Input: SHA-256 hex, one per line (what `genra-av hashes dump` prints). Lines that are not 64 hex
characters are skipped. `INSERT OR IGNORE`, so loading the same list again changes nothing; batches
of 500 rows keep each statement small for D1. Standard library only.
"""
import datetime
import re
import sys

HEX64 = re.compile(r"^[0-9a-f]{64}$")
BATCH = 500


def hashes(paths):
    seen = set()
    for p in paths:
        with open(p, encoding="ascii", errors="replace") as f:
            for line in f:
                h = line.strip().lower()
                if HEX64.match(h) and h not in seen:
                    seen.add(h)
                    yield h


def statements(source: str, hs, now: str):
    if not re.match(r"^[a-z0-9_-]{1,32}$", source):
        raise ValueError("source: 1-32 of a-z 0-9 _ -")
    batch = []
    for h in hs:
        batch.append(f"('{h}','{h[:5]}','{source}','{now}')")
        if len(batch) == BATCH:
            yield "INSERT OR IGNORE INTO known_bad (sha256, prefix, source, added_at) VALUES " + ",".join(batch) + ";"
            batch = []
    if batch:
        yield "INSERT OR IGNORE INTO known_bad (sha256, prefix, source, added_at) VALUES " + ",".join(batch) + ";"


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for s in statements(argv[1], hashes(argv[2:]), now):
        print(s)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
