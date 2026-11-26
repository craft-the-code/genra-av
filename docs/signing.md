# Code signing

| Platform | Status | How |
|---|---|---|
| macOS | Signed and notarised | Developer ID "Hoan Le (ZJSCM99CY3)", `release.yml` |
| Windows | **Unsigned until SignPath approves** | SignPath Foundation (free for open source); publisher shows as "SignPath Foundation" |
| Linux | Not signed (AppImage/deb) | SHA256SUMS and build attestations |
| All | Build provenance | GitHub artifact attestations; `gh attestation verify <file> --repo craft-the-code/genra-av` |

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org) (once approved; Windows installers before that are unsigned).

- Committers and reviewers: [members of craft-the-code](https://github.com/orgs/craft-the-code/people)
- Approvers: [owners of craft-the-code](https://github.com/orgs/craft-the-code/people?query=role%3Aowner)

Every signed file is built by GitHub Actions from a `v*` tag of this repository (`release.yml`), and
every signing request is approved by hand. Changes from people outside the team are reviewed by a team
member before they are merged.

Privacy: [privacy policy](https://craftthecode.dev/genra/privacy). Genra AV sends nothing by default.
It downloads signed rule packs and checks for updates from GitHub; hashes of detected files and
false-positive reports are sent only when the user turns that on or presses "báo nhầm".

## Applying to SignPath Foundation (Hoan)

Conditions (signpath.org/terms) and where Genra stands:

| Condition | Genra AV |
|---|---|
| OSI licence, no proprietary parts | Apache-2.0, all dependencies open source |
| Already released in the form to sign | Yes: NSIS `.exe` and `.msi` on GitHub Releases since 0.1.0 |
| Functionality documented on the download page | README and craftthecode.dev/genra |
| Team owns repository and build scripts | Yes |
| No hacking or vulnerability-scanning tools | Genra reads files to find malware; it does not exploit or probe systems |
| Privacy: data sent only as documented, can be turned off | Off by default, privacy policy linked above |
| Uninstaller | NSIS and MSI both uninstall from Settings → Apps |
| MFA for every team member on GitHub and SignPath | **Check: GitHub → Settings → Password and authentication** |
| Roles: authors, reviewers, approvers | Listed above (Hoan holds all three for now) |
| Builds from source, verifiable; manual approval per release | GitHub Actions on GitHub-hosted runners, tag-only `release` environment |

Steps:

1. Turn on two-factor authentication on GitHub for every member of craft-the-code.
2. Apply at <https://signpath.org/apply> with:
   - Project: Genra AV, <https://github.com/craft-the-code/genra-av>, Apache-2.0.
   - Description: free antivirus for the Office macro worms and downloader files that Vietnamese
     offices receive over Zalo, email and USB; cleans infected documents and undoes every change.
   - Artifacts to sign: `Genra-AV-Setup.exe` (NSIS, per user) and `Genra-AV.msi`, built by
     `.github/workflows/release.yml` on `windows-latest`.
   - Download page: <https://github.com/craft-the-code/genra-av/releases> and <https://craftthecode.dev/genra>.
3. After approval: create the SignPath project `genra-av` with signing policy `release-signing`, put
   `SIGNPATH_API_TOKEN` in the `release` environment, and uncomment the SignPath steps in `release.yml`
   (organization id from SignPath). Product name in the file metadata is "Genra AV" and the version is
   the tag's, as the terms require.
4. Cut 1.0.0: the release workflow signs the Windows installers, re-signs the updater files over the
   signed installers, and publishes an official (non-pre-release) release.
