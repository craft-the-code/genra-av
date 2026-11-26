# ADR 0002: detection ships as signed rule packs, not app releases

Status: accepted in P0 (format 1). Delivery channel built in P2.

## Context

A new worm can spread across a province in a day. Shipping a signed installer for every new rule
takes days and needs every user to update. The app must learn new threats without an app update,
and a bad rule must be pulled back just as fast.

## Decision

- Rules are data: `rules/*.json` (format 1), conditions on file hash, VBA module names and VBA
  source substrings. YARA-X sources join the pack in P3 as a second rule kind.
- Each pack is signed with Ed25519 over its exact bytes (`<pack>.sig`). Clients carry the public
  keys in the binary and refuse any pack that does not verify (tested: one changed digit → refused).
- `version` is monotonic, and clients enforce it: each install keeps the highest version it accepted
  (`PackState`, in the data folder) and refuses an older pack, or another pack with the same version
  (rollback attack). The CI derives the next version from the published pack: max(previous + 1,
  UTC `YYYYMMDDHH`).
- Every signed pack carries `expires` (RFC 3339 or Unix seconds), covered by the signature; clients
  refuse a signed pack with no `expires` or one past it (freeze attack: an attacker who blocks
  updates cannot keep a machine on an old pack forever). The CI sets now + 14 days. Unsigned
  development packs (`--unsigned`) may leave it out.
- A client that cannot verify a new pack (bad signature, expired, older, a hash list that does not
  match its digest) keeps its previous pack. A half-published pack therefore costs nothing: assets go
  up as the versioned hash list (`malwarebazaar-<version>.bin`) first, then `pack.json`, then
  `pack.json.sig` last. The CLI warns and scans with rules and heuristics only when a hash list fails.
- Two brakes in every pack: `disabled` (rule ids switched off) and `allow_sha256` (known-good files),
  so a false positive is fixed by publishing a pack, not by an app release.
- Delivery (P2): a static manifest on a CDN, polled hourly with jitter; full pack under ~1 MB, so no
  delta format until size demands it. Staged rollout: the manifest names the share of clients
  (by install-id hash) that take a new pack, 5% → 50% → 100%.
- Hash lists from public feeds (MalwareBazaar) are `suspicious`, never `malware`, and never move a
  file into quarantine on their own: anyone can upload a clean, widely used file to such a feed. Only
  a hand-written rule, a built-in heuristic, or a list marked `trusted: true` (curated by us, every
  entry reviewed) can quarantine.
- Two kinds of pack change, two paths:
  - Hand-written rules (`rules/base.json`), allow list and kill switch: only through a reviewed pull
    request to `main`.
  - Automated hash feeds: folded in and signed by CI every 6 hours (`.github/workflows/rule-pack.yml`).
    The build job (cargo, third-party crates, read-only token) produces an unsigned pack. The
    `sign-publish` job runs in the protected `rule-pack` environment, deployable from `main` only,
    which alone holds the signing key. It runs no cargo or third-party code: it checks the unsigned
    pack equals `rules/base.json` apart from the generated fields and one untrusted `suspicious` hash
    set, that the version grows and the list does not shrink, then signs with openssl and verifies
    against `keys/pack-1.pub` before publishing.
- Keys: `pack-1` signs in CI from the `rule-pack` environment; a copy lives in the maintainer's
  1Password for local signing (`genra-av rules sign`). `pack-2` is embedded from day one as the standby
  so the first can be rotated without an app update.

## Consequences

- Built-in heuristics remain in the binary, so a fresh or offline install still flags auto-run macros.
- Whoever holds the signing key can make every client flag any file: two-person review on hand-written
  rules, and the CI key can only add `suspicious` hashes that never quarantine.
- A client offline for more than 14 days stops using its pack (built-in heuristics still run) until it
  fetches a fresh one.
