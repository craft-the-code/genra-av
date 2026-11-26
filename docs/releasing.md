# Releasing Genra AV

A release is a pushed tag `v<x.y.z>`. The workflow [`.github/workflows/release.yml`](../.github/workflows/release.yml)
builds the installers on GitHub's Windows, macOS and Linux runners and publishes a GitHub Release.
Plan and decisions: [release-plan.md](release-plan.md).

## Cut a release

1. **Bump the version** everywhere it is written (Cargo.toml, Cargo.lock, tauri.conf.json,
   app/package.json, app/package-lock.json):

   ```bash
   python3 scripts/bump-version.py 0.1.0
   python3 scripts/check-version.py v0.1.0      # prints 0.1.0, or what does not match
   ```

   Numbers only (`0.1.0`, not `0.1.0-beta.1`): the MSI installer refuses other versions.

2. **Changelog.** In `CHANGELOG.md`, rename `## [Unreleased]` to `## [0.1.0] - YYYY-MM-DD` and add a
   new empty `## [Unreleased]` above it. That section becomes the release notes; check it with

   ```bash
   python3 scripts/release-notes.py CHANGELOG.md 0.1.0
   ```

3. **Merge** the bump and changelog through a pull request to `main`.

4. **Tag** the merge commit on `main` and push the tag:

   ```bash
   git fetch origin && git checkout origin/main
   git tag -a v0.1.0 -m "Genra AV 0.1.0"
   git push origin v0.1.0
   ```

5. Watch the run: `gh run watch --repo craft-the-code/genra-av` (or the Actions tab). About 20–40
   minutes; notarisation can add more.

To run the workflow again for an existing tag (for example after deleting a failed release), run it
**from the tag**, since the `release` environment accepts tags only:

```bash
gh release delete v0.1.0 --repo craft-the-code/genra-av --yes   # the release, not the tag
gh workflow run release.yml --repo craft-the-code/genra-av --ref v0.1.0 -f tag=v0.1.0
```

## What the workflow does

| Job | Runs on | Does |
|---|---|---|
| guard | ubuntu-latest, read-only | Tag is `v<x.y.z>` and equals every version in the repo (`check-version.py`); `CHANGELOG.md` has its section. Fails before anything is built. |
| build ×3 | windows-latest, macos-latest, ubuntu-22.04; read-only token; environment `release` | `npm ci`, then `npx tauri build --config src-tauri/tauri.release.conf.json`. Windows: NSIS `.exe` (per user, no admin) + `.msi`. macOS: universal `.dmg` (`--target universal-apple-darwin`). Linux: `.AppImage` + `.deb`. Copies each file to a fixed name and a versioned name (`collect-bundles.py`) and uploads them as artifacts. |
| publish | ubuntu-latest; environment `release`; `contents: write`, `id-token: write`, `attestations: write` | Downloads the artifacts, writes `latest.json` (updater), `SHA256SUMS`, a build provenance attestation over every file, and the notes (CHANGELOG section + downloads, signing status, how to verify). Creates a draft release with all files and publishes it once every upload has succeeded. 0.x versions are marked **pre-release**. |

Release-only Tauri settings live in [`app/src-tauri/tauri.release.conf.json`](../app/src-tauri/tauri.release.conf.json),
merged over `tauri.conf.json` at build time: bundle targets, NSIS per-user install, the fixed WiX
upgrade code (must never change), and the updater public key and endpoint.

Files on every release:

| File | What |
|---|---|
| `Genra-AV-Setup.exe`, `Genra-AV.msi`, `Genra-AV.dmg`, `Genra-AV.AppImage`, `genra-av.deb` | fixed names, for `releases/latest/download/<file>` links |
| `Genra-AV_<v>_x64-setup.exe`, `Genra-AV_<v>_x64_en-US.msi`, `Genra-AV_<v>_universal.dmg`, `Genra-AV_<v>_amd64.AppImage`, `genra-av_<v>_amd64.deb` | the same bytes under versioned names |
| `Genra-AV_<v>_universal.app.tar.gz`, `*.sig`, `latest.json` | updater files, only when the updater key is configured |
| `SHA256SUMS` | SHA-256 of every other file |

Verify a download: `sha256sum --check --ignore-missing SHA256SUMS` and
`gh attestation verify Genra-AV.dmg --repo craft-the-code/genra-av`.

### Pre-releases and `latest`

GitHub's `releases/latest` (and so `releases/latest/download/<file>`) skips pre-releases. While
versions are 0.x, those links and the updater endpoint in `tauri.release.conf.json` do not resolve;
link testers to the tag instead (`releases/download/v0.1.0/Genra-AV.dmg`) or to the release page.
They start working with the first release that is not a pre-release (1.0.0, or a 0.x release
edited with `gh release edit v0.x.y --prerelease=false --latest`).

## Signing

| OS | Status | How |
|---|---|---|
| macOS | signed + notarised when all six `APPLE_*` secrets exist; otherwise built unsigned (ad-hoc) and the notes say so | The `.p12` is imported into a temporary keychain that is deleted at the end of the job. Tauri signs the `.app` with `APPLE_SIGNING_IDENTITY` (hardened runtime) and notarises and staples it with the App Store Connect API key. The workflow then signs, notarises and staples the `.dmg` itself and checks both with `spctl`. |
| Windows | **unsigned** for the beta | SmartScreen warns. `release.yml` carries a commented SignPath step after `tauri build`; enable it once SignPath Foundation approves the project (release-plan.md). |
| Linux | unsigned | — |
| Updater | signed when `TAURI_SIGNING_PRIVATE_KEY` exists; otherwise no updater files and no `latest.json` | `createUpdaterArtifacts` is switched on only then. The public key in the overlay must match the private key, or the build fails. |

Secrets are passed to each step only as environment variables, exported to Tauri only when used,
and never printed. The build jobs run npm and cargo dependencies with the signing secrets present
(Tauri signs inside `tauri build`); the token in those jobs is read-only and there is no build cache.

## Environment and secrets

Everything lives in the GitHub environment **`release`**, which only tags matching `v*` may deploy
to. Set up once on 26/11/2026; the commands below are for a new repository or a key rotation. Run
them from a trusted machine; secret values are read from files or prompted, never put on the
command line.

```bash
R=craft-the-code/genra-av

# Environment limited to tags (no branch may deploy).
gh api -X PUT "repos/$R/environments/release" \
  -F 'deployment_branch_policy[protected_branches]=false' \
  -F 'deployment_branch_policy[custom_branch_policies]=true'
gh api -X POST "repos/$R/environments/release/deployment-branch-policies" -f name='v*' -f type=tag
gh api "repos/$R/environments/release/deployment-branch-policies"   # check
# Optional: require a reviewer before each release job runs.
# gh api -X PUT "repos/$R/environments/release" --input - <<<'{"reviewers":[{"type":"User","id":<your user id>}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
```

**Updater key** (its own keypair, not the rule-pack key). Generate once, keep the private key out
of Git (back it up in the password manager), and put the public key in the overlay:

```bash
npx --prefix app tauri signer generate -w ~/keys/genra-av/updater.key     # prompts for a password
gh secret set TAURI_SIGNING_PRIVATE_KEY --env release --repo "$R" < ~/keys/genra-av/updater.key
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD --env release --repo "$R"   # prompts
cat ~/keys/genra-av/updater.key.pub   # paste into plugins.updater.pubkey in tauri.release.conf.json
```

Rotating it breaks updates for installed apps that only know the old public key: ship one release
signed with the old key whose app trusts the new one first.

**Apple** (Developer ID Application certificate, exported from Keychain Access as `.p12`; App Store
Connect API key with the Developer role, from Users and Access → Integrations → Keys):

```bash
base64 -i DeveloperID.p12 | gh secret set APPLE_CERTIFICATE --env release --repo "$R"
gh secret set APPLE_CERTIFICATE_PASSWORD --env release --repo "$R"     # the .p12 export password
gh secret set APPLE_SIGNING_IDENTITY --env release --repo "$R" --body 'Developer ID Application: <Name> (<TEAMID>)'
gh secret set APPLE_API_KEY_ID --env release --repo "$R"               # e.g. 2X9R4HXF34
gh secret set APPLE_API_ISSUER --env release --repo "$R"               # issuer UUID
base64 -i AuthKey_<KEYID>.p8 | gh secret set APPLE_API_KEY --env release --repo "$R"
gh secret list --env release --repo "$R"
```

Leave any of the six unset and macOS is built unsigned; the release notes then say so.

## Checked locally and not

`actionlint` and `shellcheck` pass; the scripts are standard-library Python and were run on fake
bundles. A macOS `--bundles dmg` build with the overlay was made locally and verified with
`hdiutil verify`. The Windows and Linux jobs, signing, notarisation, the updater signatures and the
publish job run only on GitHub, so the first real tag is their first test.
