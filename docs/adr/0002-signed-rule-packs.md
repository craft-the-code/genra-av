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
- `version` is monotonic; a client never replaces a pack with an older one (rollback attack).
- Two brakes in every pack: `disabled` (rule ids switched off) and `allow_sha256` (known-good files),
  so a false positive is fixed by publishing a pack, not by an app release.
- Delivery (P2): a static manifest on a CDN, polled hourly with jitter; full pack under ~1 MB, so no
  delta format until size demands it. Staged rollout: the manifest names the share of clients
  (by install-id hash) that take a new pack, 5% → 50% → 100%.
- Keys: the signing key lives in the maintainer's 1Password and signs on one machine; a second key is
  embedded from day one so the first can be rotated without an app update.

## Consequences

- Built-in heuristics remain in the binary, so a fresh or offline install still flags auto-run macros.
- Whoever holds the signing key can make every client flag any file: two-person review on packs.
