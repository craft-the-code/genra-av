#!/usr/bin/env python3
"""Release guard: the tag must name the version written in the repository. Standard library only.

Usage: check-version.py <tag>        e.g. check-version.py v0.1.0

Fails unless the tag is v<x.y.z> (numbers only: the MSI installer refuses suffixes) and every
place the version is written (see release_version.py) holds exactly x.y.z. Prints the version.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import release_version as rv  # noqa: E402


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-version.py <tag>")
    tag = sys.argv[1]
    if not tag.startswith("v") or not rv.SEMVER.match(tag[1:]):
        raise SystemExit(f"tag {tag!r} is not v<x.y.z> (numbers only, no suffix)")
    version = tag[1:]
    bad = {label: v for label, v in rv.current_versions().items() if v != version}
    if bad:
        lines = "\n".join(f"  {label}: {v}" for label, v in bad.items())
        raise SystemExit(
            f"tag {tag} does not match the version in the repository:\n{lines}\n"
            f"Run scripts/bump-version.py {version}, commit, and tag that commit."
        )
    print(version)


if __name__ == "__main__":
    main()
