#!/usr/bin/env bash
# The detection report's rule pack: the published signed pack with its hash lists and YARA rules,
# into <dir>. With "preview" (a branch run before the rules are published), also builds the YARA
# rules here and adds them to an unsigned copy of the pack. Prints the scan flags to use.
#   get-pack.sh <dir> <genra-av CLI> [preview]
set -euo pipefail
dir=$1
cli=$2
mode=${3:-}
here=$(cd "$(dirname "$0")/.." && pwd)
py=$(command -v python3 || command -v python)
gh release download rules-latest -p pack.json -p pack.json.sig -D "$dir"
"$py" -c 'import json,sys; p=json.load(open(sys.argv[1], encoding="utf-8")); [print(s["file"]) for s in p.get("hash_sets", [])]; y=p.get("yara"); y and print(y["file"])' "$dir/pack.json" | tr -d '\r' > "$dir/files"
grep -qvE '^([A-Za-z0-9._-]+\.bin|yara-[0-9a-f]{12}\.yar)$' "$dir/files" && { echo "odd file name in the pack" >&2; exit 1; }
while read -r f; do gh release download rules-latest -p "$f" -D "$dir"; done < "$dir/files"
if [ "$mode" = preview ]; then
  "$here/yara-build.sh" build "$dir" "$cli" >&2
  "$py" -c 'import json,sys; p=json.load(open(sys.argv[1], encoding="utf-8")); y=json.load(open(sys.argv[2], encoding="utf-8")); p["yara"]=y; json.dump(p, open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False)' "$dir/pack.json" "$dir/yara.json"
  echo "--rules $dir/pack.json --unsigned"
else
  echo "--rules $dir/pack.json --pubkey keys/pack-1.pub"
fi
