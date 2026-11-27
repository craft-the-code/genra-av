#!/usr/bin/env bash
# The pack's YARA rule file, from the latest YARA Forge "core" release and ReversingLabs' rules
# (ADR 0004, layer 2; licences in rules/yara-sources.json, docs/yara-rules.md).
#
#   yara-build.sh build <out-dir> <genra-av CLI>
#       Downloads the newest sources, keeps the licensed rules, asks Genra's engine which rules it
#       refuses, writes <out-dir>/yara-<sha12>.yar, yara.json (file, sha256, rules, source) and
#       yara-source.json (Forge tag, ReversingLabs commit, refused rule names).
#   yara-build.sh reproduce <out-dir> <yara-source.json>
#       The signing job: downloads the same tag and commit itself and rebuilds the file with the
#       standard library only, taking from the build job nothing but the list of refused rules
#       (which can only remove rules). The caller compares the result with the build job's file.
# Needs gh (GH_TOKEN), unzip, tar, python3 (or python on Windows).
set -euo pipefail

mode=$1
out=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
py=$(command -v python3 || command -v python)

if [ "$mode" = build ]; then
  cli=$3
  tag=$(gh release view --repo YARAHQ/yara-forge --json tagName --jq .tagName)
  commit=$(gh api repos/reversinglabs/reversinglabs-yara-rules/commits/HEAD --jq .sha)
elif [ "$mode" = reproduce ]; then
  src=$3
  tag=$("$py" -c 'import json,sys; print(json.load(open(sys.argv[1]))["forge_tag"])' "$src")
  commit=$("$py" -c 'import json,sys; print(json.load(open(sys.argv[1]))["rl_commit"])' "$src")
else
  echo "usage: yara-build.sh build|reproduce <out-dir> <cli|yara-source.json>" >&2
  exit 2
fi
# Both values go into URLs and file headers: digits only for the tag, a hex commit.
[[ "$tag" =~ ^[0-9]{8}$ ]] || { echo "odd YARA Forge tag: $tag" >&2; exit 1; }
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "odd ReversingLabs commit: $commit" >&2; exit 1; }
# GitHub serves a fork's commits through the parent repository's URLs too: the commit must be on
# ReversingLabs' own default branch, or anyone could get rules of their choice built here.
branch=$(gh api repos/reversinglabs/reversinglabs-yara-rules --jq .default_branch)
# compare/BASE...HEAD: "behind" means HEAD (the commit) is an ancestor of BASE (the branch tip);
# a fork's commit reads "diverged", or "ahead" when built on top of the tip (measured 27/11).
status=$(gh api "repos/reversinglabs/reversinglabs-yara-rules/compare/$branch...$commit" --jq .status)
[ "$status" = behind ] || [ "$status" = identical ] || { echo "commit $commit is not on ReversingLabs' $branch ($status)" >&2; exit 1; }

gh release download "$tag" --repo YARAHQ/yara-forge -p yara-forge-rules-core.zip -D "$work"
unzip -oq "$work/yara-forge-rules-core.zip" -d "$work/forge"
forge="$work/forge/packages/core/yara-rules-core.yar"
test -s "$forge"
gh api "repos/reversinglabs/reversinglabs-yara-rules/tarball/$commit" > "$work/rl.tgz"
mkdir "$work/rl"
tar -xzf "$work/rl.tgz" -C "$work/rl" --strip-components=1
test -d "$work/rl/yara"
# Links in a downloaded archive could pull in files from this runner.
if [ -n "$(find "$work/forge" "$work/rl" -type l -print -quit)" ]; then echo "the sources hold symbolic links" >&2; exit 1; fi

"$py" "$root/scripts/yara_select.py" select "$root/rules/yara-sources.json" "$root/rules/yara-disabled.json" "$work/blocks.yar" \
  --forge "$forge" --forge-tag "$tag" --rl "$work/rl/yara" --rl-commit "$commit"

if [ "$mode" = build ]; then
  "$cli" yara check "$work/blocks.yar" > "$work/refused.txt"
  "$py" -c 'import json,sys; print(json.dumps({"forge_tag": sys.argv[1], "rl_commit": sys.argv[2], "refused": [l.strip() for l in open(sys.argv[3]) if l.strip()]}, indent=2))' \
    "$tag" "$commit" "$work/refused.txt" > "$out/yara-source.json"
else
  "$py" -c 'import json,re,sys; r=json.load(open(sys.argv[1]))["refused"]; assert all(re.fullmatch(r"[A-Za-z0-9_]+", n) for n in r); print("\n".join(r))' "$src" > "$work/refused.txt"
fi
"$py" "$root/scripts/yara_select.py" assemble "$work/blocks.yar" "$work/refused.txt" "$root/rules/yara-malware.json" "$root/rules/licenses" "$out" > "$out/yara.json"
# No rule left (the engine refused the whole set) is a failure, so the previous rules are kept.
"$py" -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["rules"] > 0 else "no YARA rule left")' "$out/yara.json"
cat "$out/yara.json"
