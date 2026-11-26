#!/usr/bin/env python3
"""Check an unsigned pack before it is signed. Standard library only: this runs in the signing
job, which holds the key and runs no third-party code.

Usage: check-pack.py <rules/base.json> <out/pack.json> [<prev/pack.json>]

The build job runs cargo and every crate it pulls in, so its output is not trusted. The only
thing it may contribute is the hash list; everything else must equal the reviewed base.json
from this commit. Refuses:
- any field other than version/published/expires/hash_sets that differs from base.json;
- a hash set other than one untrusted, `suspicious` MalwareBazaar list named
  malwarebazaar-<version>.bin whose bytes, digest and count match and that is strictly sorted;
- a version not above the previous published pack, or an expiry not within 15 days;
- fewer hashes than the previous pack (a feed outage must not shrink the list).
The previous pack's signature is checked with openssl before this script reads it.
"""
import datetime
import hashlib
import json
import os
import sys

GENERATED = {"version", "published", "expires", "hash_sets"}


def fail(msg: str) -> None:
    sys.exit(f"check-pack: {msg}")


def main() -> None:
    base_path, pack_path = sys.argv[1:3]
    prev_path = sys.argv[3] if len(sys.argv) > 3 else None
    base = json.load(open(base_path, encoding="utf-8"))
    pack = json.load(open(pack_path, encoding="utf-8"))

    if set(pack) - GENERATED != set(base) - GENERATED:
        fail(f"fields differ from base.json: {sorted(set(pack) ^ set(base))}")
    for k in set(base) - GENERATED:
        if pack[k] != base[k]:
            fail(f"field {k!r} differs from base.json")
    if base.get("hash_sets"):
        fail("base.json must not carry hash_sets")

    version = pack["version"]
    if not isinstance(version, int) or version < int(base.get("version", 0)):
        fail("version is not an integer at or above base.json's")
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = datetime.datetime.strptime(pack["expires"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    if not now < expires <= now + datetime.timedelta(days=15):
        fail(f"expires {pack['expires']} is not within the next 15 days")

    sets = pack["hash_sets"]
    if len(sets) != 1:
        fail("expected exactly one hash set")
    hs = sets[0]
    allowed = {"file", "sha256", "count", "family", "severity", "source"}
    if set(hs) != allowed:
        fail(f"hash set fields {sorted(hs)} are not {sorted(allowed)}")
    if hs["severity"] != "suspicious" or hs.get("trusted"):
        fail("a public feed must be suspicious and untrusted")
    if hs["file"] != f"malwarebazaar-{version}.bin":
        fail(f"hash list name {hs['file']!r} is not malwarebazaar-{version}.bin")
    data = open(os.path.join(os.path.dirname(pack_path), hs["file"]), "rb").read()
    if hashlib.sha256(data).hexdigest() != hs["sha256"]:
        fail("hash list digest does not match the pack")
    if len(data) % 32 or len(data) // 32 != hs["count"]:
        fail("hash list count does not match the pack")
    digests = [data[i : i + 32] for i in range(0, len(data), 32)]
    if any(a >= b for a, b in zip(digests, digests[1:])):
        fail("hash list is not strictly sorted")

    if prev_path:
        prev = json.load(open(prev_path, encoding="utf-8"))
        if version <= prev["version"]:
            fail(f"version {version} is not above the published {prev['version']}")
        prev_count = sum(int(s.get("count", 0)) for s in prev.get("hash_sets", []))
        if hs["count"] < prev_count:
            fail(f"hash list shrank: {hs['count']} < previous {prev_count}")
        print(f"previous: version {prev['version']}, {prev_count} hashes")
    print(f"ok: version {version}, {hs['count']} hashes, expires {pack['expires']}")


if __name__ == "__main__":
    main()
