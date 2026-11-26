# Release plan: v0.1 (beta) → v1.0 (public, open source)

Written 26/11/2026. Decisions marked (Hoan) are his; the rest are proposals until he says otherwise.

## v0.1 beta: a real first release, not only Office files

Scope (Hoan, 26/11): the first release must already feel like an antivirus.

1. **Kiểm tra tệp + Dọn sạch giúp tôi**: drag-and-drop check; clean the file *and* the machine
   (Kangatang and kin out of Excel's startup, other infected workbooks cleaned, verified); quarantine + undo 30 days.
2. **Quét nhanh máy + danh tiếng hash**: Downloads, Desktop, Documents, Zalo received files, USB drives;
   public malware hashes (e.g. abuse.ch MalwareBazaar) and YARA-X rules for scripts, LNK, HTA,
   archives and PDF, all inside the signed pack.
3. **Rà soát khởi động + dọn**: everything that starts with Windows (Run keys, Startup folders,
   Scheduled Tasks, services, XLSTART, Office add-ins), suspicious ones flagged, removable with undo.
4. **Sức khoẻ máy**: Defender on and up to date, Windows Update, Office macro setting, firewall, with "Sửa giúp tôi".
5. **Canh gác thư mục + USB**: the `genra-guard` background process checks new files in those folders
   and on USB insert, and notifies only when there is something to do.

Plus: app auto-update, Vietnamese + English, light theme, report / false-positive button (backend live).
Later (v0.2+): rule updates over the CDN between app releases, static ML on executables, behaviour layer.

Audience: a small group of testers. Windows installer **unsigned** for the beta (SignPath applied for once CI builds exist),
macOS signed + notarised (existing Apple Developer account).

Risky item first: **cleaning a `.xls` without losing its formatting.** Options to spike:
remove the VBA storage and the module sheet's BOUNDSHEET record from the BIFF8 workbook (keeps
everything, hard), convert to `.xlsx` (needs a spreadsheet engine), or values-only copy (loses format).

## Installers (Tauri 2 bundler)

| OS | Artefacts | Signing |
|---|---|---|
| Windows | `.exe` (NSIS, per-user, no admin) + `.msi` (IT / Group Policy) | beta: none; v1.0: SignPath Foundation (free, needs public OSS) or Certum Open Source (~€69/yr) |
| macOS | universal `.dmg` | Developer ID + notarisation |
| Linux | `.AppImage` + `.deb` | none |

Azure Artifact Signing (ex-Trusted Signing, ~$9.99/month) is dropped: monthly cost for a few signings,
and individual eligibility outside the US/Canada is unclear (Hoan, 26/11: too expensive for the use).

Builds: GitHub Actions, `.github/workflows/release.yml`, on a `v<x.y.z>` tag: Windows, macOS
(universal) and Linux runners, free for the public repo. How to cut a release, what is signed and
the `release` environment: [releasing.md](releasing.md).

## Downloads: GitHub Releases (Hoan, 26/11)

- Every release is a GitHub Release with all installers, `SHA256SUMS`, build attestations and the
  release notes copied from `CHANGELOG.md` (Keep a Changelog, SemVer).
- Stable links for the landing page: `https://github.com/craft-the-code/genra-av/releases/latest/download/<file>`
  with fixed file names per OS (`Genra-AV-Setup.exe`, `Genra-AV.msi`, `Genra-AV.dmg`, `Genra-AV.AppImage`, `genra-av.deb`).
- The Tauri updater reads `latest.json` from the latest release (its own minisign keypair, public
  key in `app/src-tauri/tauri.release.conf.json`; wiring the updater plugin into the app is still to do).
- 0.x releases are GitHub **pre-releases**. `releases/latest` skips pre-releases, so the fixed
  `latest/download` links and the updater endpoint only resolve from the first non-pre-release;
  until then, link testers to the tag (`releases/download/v0.1.0/<file>`).
- Landing page: craftthecode.dev gets a Genra AV page with per-OS download buttons, changelog link,
  **FAQ**, **privacy policy** and **terms**, once v0.1 is released.

## Backend: Cloudflare (live since 26/11)

- **Worker + D1 + R2** at `genra-api.craftthecode.dev` (`backend/`, PR #1):
  - `POST /v1/report`: bug / false positive. Hash, rule id, app version, OS, user note, optional email.
  - `POST /v1/sample`: sample for analysis, **only the extracted VBA project, never the document's
    cells** (officers' files hold personal data). Explicit consent per file, size cap, 90-day retention.
  - Rate limit per install id; no accounts.
- Packs (`/packs/manifest.json`, signed) on R2 in v0.2.
- Admin and insights: `/admin/*` behind Cloudflare Access (docs/strategy.md).

Domain (Hoan, 26/11): use `craftthecode.dev` for now, first-level subdomains so Cloudflare's free
certificate covers them: `genra-api.craftthecode.dev` (Worker), `genra-dl.craftthecode.dev` (R2).

## Legal pages (before anything is public)

- **Chính sách quyền riêng tư / Privacy policy**, written to Nghị định 13/2023/NĐ-CP: what is
  collected (nothing by default; hashes if opted in; reports and VBA-only samples when the user
  sends them), purpose, retention, the user's rights, contact.
- **Điều khoản sử dụng / Terms**: free software, no warranty, a companion to Windows Defender and not a
  replacement, limits of liability, how rule packs and updates work.
- In the app: links in About, first-run screen with the opt-in for hash reports (default off).

## Public on GitHub (done 26/11, moved up from v1.0)

Hoan, 26/11: open source now, Apache-2.0, public at github.com/craft-the-code/genra-av; work goes
through branches and pull requests from `main`. GitLab `craft-the-code/genra-av` is no longer used.
Free signing and free CI both need a public open-source repo, which this unlocks early:

1. Public repo on GitHub, Apache-2.0 (Q9).
2. **GitHub Actions** builds all installers: Windows, macOS and Linux runners are free for public
   repos, so macOS no longer needs Hoan's Mac. Done: `release.yml`; Apple and updater secrets are in
   the `release` environment, which only `v*` tags may use (26/11).
3. **GitHub Releases** host the installers, with stable links
   `github.com/<org>/genra-av/releases/latest/download/<file>` for the landing page. R2 is then only
   needed for rule packs and the backend.
4. **Windows signing, free:** SignPath Foundation for the direct-download `.exe`/`.msi` (publisher
   shows as "SignPath Foundation"); fallback Certum Open Source (~€28–69/yr, sources disagree).
5. **Microsoft Store** as a second Windows channel: individual registration is free since 09/2025 and
   the Store re-signs MSIX packages itself. Check Store policy for a security app with a background guard.
6. Sigstore / GitHub artifact attestations for build provenance (does not replace Authenticode).
7. Landing page entry with per-OS download buttons, privacy and terms links.

## Open (for review later)

- Colour (Hoan, 26/11): the all-white light theme feels plain; most products carry one brand colour
  (e.g. a navy/blue sidebar). Revisit before v1.0.
