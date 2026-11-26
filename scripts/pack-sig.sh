#!/usr/bin/env bash
# Sign or verify a rule pack with openssl only (no Rust, no third-party code), so the CI job that
# holds the signing key runs nothing but the runner's own tools. The output is the same hex
# Ed25519 signature `genra-av rules sign` writes, and `Pack::verified` accepts it.
#
#   SIGNING_KEY=<64 hex seed> scripts/pack-sig.sh sign   <pack.json> <keys/pack-1.pub>
#                             scripts/pack-sig.sh verify <pack.json> <keys/pack-1.pub>
#
# sign writes <pack.json>.sig and then verifies it against the public key.
set -euo pipefail
mode=$1 pack=$2 pub=$3
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
umask 077

unhex() { python3 -c 'import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))'; }

pem() { # <label> <hex DER>; the hex goes through stdin, never a command line
  printf -- '-----BEGIN %s-----\n%s\n-----END %s-----\n' "$1" "$(printf '%s' "$2" | unhex | base64 | tr -d '\n')" "$1"
}

verify() {
  pubhex=$(tr -d ' \n\r' < "$pub")
  [[ $pubhex =~ ^[0-9a-f]{64}$ ]] || { echo "public key is not 32 bytes of hex" >&2; exit 1; }
  # SubjectPublicKeyInfo for Ed25519 = 302a300506032b6570032100 || 32-byte key
  pem "PUBLIC KEY" "302a300506032b6570032100$pubhex" > "$tmp/pub.pem"
  tr -d ' \n\r' < "$pack.sig" | unhex > "$tmp/sig.bin"
  [[ $(wc -c < "$tmp/sig.bin") -eq 64 ]] || { echo "signature is not 64 bytes" >&2; exit 1; }
  openssl pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin -in "$pack" -sigfile "$tmp/sig.bin" >/dev/null
  echo "signature ok: $pack"
}

case $mode in
  sign)
    seed=${SIGNING_KEY:?SIGNING_KEY is not set}
    seed=$(printf '%s' "$seed" | tr -d ' \n\r')
    [[ $seed =~ ^[0-9a-fA-F]{64}$ ]] || { echo "SIGNING_KEY is not 32 bytes of hex" >&2; exit 1; }
    # PKCS#8 PrivateKeyInfo for Ed25519 = 302e020100300506032b657004220420 || 32-byte seed
    pem "PRIVATE KEY" "302e020100300506032b657004220420$seed" > "$tmp/key.pem"
    unset seed
    openssl pkeyutl -sign -inkey "$tmp/key.pem" -rawin -in "$pack" -out "$tmp/sig.bin"
    rm -f "$tmp/key.pem"
    od -An -v -tx1 "$tmp/sig.bin" | tr -d ' \n' > "$pack.sig"
    verify
    ;;
  verify) verify ;;
  *) echo "usage: $0 sign|verify <pack.json> <pubkey>" >&2; exit 2 ;;
esac
