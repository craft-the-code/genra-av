#!/usr/bin/env python3
"""Check an unsigned pack before it is signed. Standard library only: this runs in the signing
job, which holds the key and runs no third-party code.

Usage: check-pack.py <rules/base.json> <out/pack.json> [<prev/pack.json>] [--additions <file>]

The build job runs cargo and every crate it pulls in, so its output is not trusted. The only
thing it may contribute is the hash list; everything else must equal the reviewed base.json
from this commit. Refuses:
- any field other than version/published/expires/hash_sets that differs from base.json;
- hash sets other than: optionally a trusted `malware` list named trusted-<version>.bin first, then
  one untrusted, `suspicious` MalwareBazaar list named malwarebazaar-<version>.bin; each with
  bytes, digest and count that match and strictly sorted;
- a trusted list that drops a hash the previous signed pack trusted (removals go through the
  pack's allow list, on review). Hashes added to the trusted list are written to --additions; the
  signing job re-checks each one with MalwareBazaar (scripts/hash_grade.py verify) before signing;
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


def read_list(folder: str, hs: dict) -> list[bytes]:
    """The list's digests, after checking its bytes against the digest and count in the pack."""
    data = open(os.path.join(folder, hs["file"]), "rb").read()
    if hashlib.sha256(data).hexdigest() != hs["sha256"]:
        fail(f"{hs['file']}: digest does not match the pack")
    if len(data) % 32 or len(data) // 32 != hs["count"]:
        fail(f"{hs['file']}: count does not match the pack")
    digests = [data[i : i + 32] for i in range(0, len(data), 32)]
    if any(a >= b for a, b in zip(digests, digests[1:])):
        fail(f"{hs['file']}: not strictly sorted")
    return digests


def main() -> None:
    args = sys.argv[1:]
    additions_path = None
    if "--additions" in args:
        i = args.index("--additions")
        additions_path = args[i + 1]
        del args[i : i + 2]
    base_path, pack_path = args[0:2]
    prev_path = args[2] if len(args) > 2 else None
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
    if not 1 <= len(sets) <= 2:
        fail("expected the feed list, optionally after a trusted list")
    trusted = sets[0] if len(sets) == 2 else None
    hs = sets[-1]
    allowed = {"file", "sha256", "count", "family", "severity", "source"}
    if set(hs) != allowed:
        fail(f"hash set fields {sorted(hs)} are not {sorted(allowed)}")
    if hs["severity"] != "suspicious" or hs.get("trusted"):
        fail("a public feed must be suspicious and untrusted")
    if hs["file"] != f"malwarebazaar-{version}.bin":
        fail(f"hash list name {hs['file']!r} is not malwarebazaar-{version}.bin")
    digests = read_list(os.path.dirname(pack_path), hs)
    new_trusted = set()
    if trusted:
        if set(trusted) != allowed | {"trusted"} or trusted["trusted"] is not True or trusted["severity"] != "malware":
            fail("the trusted list must be malware, trusted, with the usual fields")
        if trusted["file"] != f"trusted-{version}.bin":
            fail(f"trusted list name {trusted['file']!r} is not trusted-{version}.bin")
        if trusted["family"] != "Mã độc phổ biến đã xác nhận" or trusted["source"] != "abuse.ch MalwareBazaar, corroborated":
            fail("the trusted list's family or source text changed")
        new_trusted = set(read_list(os.path.dirname(pack_path), trusted))

    if prev_path:
        prev = json.load(open(prev_path, encoding="utf-8"))
        if version <= prev["version"]:
            fail(f"version {version} is not above the published {prev['version']}")
        prev_sets = prev.get("hash_sets", [])
        prev_feed = [x for x in prev_sets if not x.get("trusted")]
        prev_count = sum(int(x.get("count", 0)) for x in prev_feed)
        if hs["count"] < prev_count:
            fail(f"hash list shrank: {hs['count']} < previous {prev_count}")
        prev_trusted = set()
        for x in prev_sets:
            if x.get("trusted"):
                prev_trusted |= set(read_list(os.path.dirname(prev_path), x))
        if prev_trusted - new_trusted:
            fail(f"the trusted list dropped {len(prev_trusted - new_trusted)} hash(es); use allow_sha256 instead")
        added = new_trusted - prev_trusted
        print(f"previous: version {prev['version']}, {prev_count} feed hashes, {len(prev_trusted)} trusted")
    else:
        added = new_trusted
    if additions_path:
        with open(additions_path, "w") as f:
            f.writelines(d.hex() + "\n" for d in sorted(added))
    print(f"ok: version {version}, {hs['count']} feed hashes, {len(new_trusted)} trusted (+{len(added)}), expires {pack['expires']}")


if __name__ == "__main__":
    main()
