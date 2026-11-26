# Release plan: v0.1 (beta) → v1.0 (public, open source)

Written 26/11/2026. Decisions marked (Hoan) are his; the rest are proposals until he says otherwise.

## v0.1 beta: "Kiểm tra + Dọn sạch"

Scope (proposal): drag-and-drop file check; **Dọn sạch giúp tôi** (clean the file, remove the
Kangatang worm from Excel's startup folder, clean other infected Excel files, verify); quarantine +
undo 30 days; rule pack bundled in the app; signed app auto-update; Vietnamese + English; light theme.
Not in v0.1: folder guard, rule updates over the CDN, health screen (→ v0.2).

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

Builds: Linux and Windows in GitLab CI (shared Linux and Windows runners); macOS on Hoan's Mac
until a macOS runner is worth paying for.

## Downloads and backend: Cloudflare (proposal; installers move to GitHub Releases at v1.0)

- **R2** public bucket behind `download.<domain>`: `/<version>/…` plus stable `/latest/windows`,
  `/latest/macos`, `/latest/linux-appimage`, `/latest/linux-deb`, and the updater manifest.
- **Worker + D1** at `api.<domain>`:
  - `POST /v1/report`: bug / false positive. Hash, rule id, app version, OS, user note, optional email.
  - `POST /v1/sample`: sample for analysis, **only the extracted VBA project, never the document's
    cells** (officers' files hold personal data). Explicit consent per file, size cap, 90-day retention.
  - Rate limit per install id; no accounts.
- Packs (`/packs/manifest.json`, signed) join the same bucket in v0.2.

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
   repos, so macOS no longer needs Hoan's Mac (Apple signing secrets go into Actions secrets).
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
