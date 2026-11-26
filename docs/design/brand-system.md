# Genra AV brand and design system (v2, 26/11/2026)

One page per decision area. App UI follows the OS (native, system fonts); marketing (landing page,
blog, video, store listings) carries more brand. Tokens: [tokens.md](tokens.md). Mock-ups v2:
[../ux/mocks/v2/overview.png](../ux/mocks/v2/overview.png). Usability rules: [../ux/usability-audit.md](../ux/usability-audit.md).

## 1. Logo

- **Mark**: the ☶ shield (docs/brand.md). Never redrawn, rotated, outlined or put on a busy photo.
- **Wordmark** "GENRA AV": convert to outlined paths before any print, installer or store asset
  (live text in the SVG is for drafts only). GENRA in the strong weight, AV lighter and muted.
- **Clear space**: the height of one ☶ bar on every side. **Minimum size**: mark 16 px, lockup 96 px wide.
- **Versions**: silver on navy (default on dark), graphite on white, one-colour `currentColor`
  (tray, menu bar, favicons), red-dot alert variant for the tray only.
- **App icon**: the mark on the navy squircle; macOS follows Apple's icon grid, Windows uses the same art unplated.

## 2. Colour

Brand is **navy + Genra Lam**, with silver for the mark; status colours mean one thing each.

| Role | Light (default) | Use |
|---|---|---|
| Navy 900 `#0A1530` | sidebar, installer, landing hero | Brand surface |
| Navy 800 → 600 `#0F1E40 → #22407F` | brand band gradient | The one brand moment per screen |
| Lam `#2F6BEF` | buttons, focus, links | The only action colour |
| Green `#16935F` icon / `#11804F` text | safe, done | Status only |
| Amber `#F5A524` icon / `#97590A` text | needs a look | Status only |
| Red `#C62F35` | malware only | Status only, never decoration |
| Neutrals `#F4F6F9` bg · `#FFFFFF` cards · `#E2E6EC` borders · `#12151B` text · `#5B6270` muted | everything else | |

Hoan, 26/11: an all-white UI felt plain; v2 gives the brand two places, the navy sidebar and the
band at the top of Tổng quan, and keeps everything else calm. No gradients outside the band.

## 3. Typography

- **App**: system fonts (Segoe UI Variable / SF Pro, Inter fallback), sizes in tokens.md, body ≥ 14 px, tabular figures for counts.
- **Marketing** (landing, blog, video titles, social cards): **Be Vietnam Pro** (OFL, designed for
  Vietnamese) for headings, system font for body. One family, two weights (600, 800).

## 4. Iconography

- One set, one style: **Lucide** (ISC licence) as the base, 24 px grid, 1.75 px stroke, round caps;
  used at 16/20/24 px. Status icons are filled circles with a glyph (✓ ! ✕), always next to a word.
- Custom icons only for brand meaning (the ☶ mark, "canh gác", "khép cổng") drawn on the same grid.
- Icons never carry meaning alone; every icon button has a text label or tooltip.

## 5. Photography

- **App: no photographs.** The UI is the product.
- **Landing / blog**: real screenshots of the app first. Photos only when real (an office, a ward,
  people who agreed); no stock "hacker in a hoodie", no padlocks, no binary rain.

## 6. Shape and the ☶ motif

- 8 px grid; radius 8 (controls), 12 (cards), 16 (hero/band, dialogs).
- **Signature motif: the trigram lines** — one solid bar over two broken bars — tiled faintly
  (≤ 8 % opacity) on the right side of the brand band, never behind text. It is the visual sign of
  "Genra is guarding the gate". Static SVG, no animation inside the app.
- The shield silhouette frames only the main status, nothing else.

## 7. Illustration

- Geometric, built from ☶ bars and the shield; two colours (navy + Lam) plus one status colour.
- Used for empty states, first run, "Máy an toàn", errors. No characters in the app (Q12); a mascot
  exists only in tutorial videos.
- Motion (Q12 B): when a threat is blocked, the gate of the mark closes in ≤ 400 ms; respects "reduce motion".

## 8. Writing (voice and tone)

- **Voice**: a calm, competent helper who does the work for you. Short sentences, everyday Vietnamese,
  "bạn" for the user, "Genra" for itself. Never "Chúng tôi"; never fear ("NGUY HIỂM!!!").
- **Every message**: what happened · what it means for you · the one thing to press. Errors also say what Genra already did.
- **Buttons say the outcome**: "Dọn sạch giúp tôi", "Đóng Excel giúp tôi", "Hoàn tác", not "OK"/"Tiếp tục".
- **Word list**: mã độc (malware), sâu (worm), cách ly (quarantine), dọn sạch (clean), hoàn tác (undo),
  canh gác (guard), báo nhầm (false-positive report), luật (rules). Technical names (Kangatang, XLSTART) only in "Xem chi tiết".
- English mirrors the same voice; strings live in `app/src/i18n/{vi,en}.json`; rule packs carry `message_vi` and `message_en`.

## 9. Presentation

- **Landing page** (craftthecode.dev/genra): hero = navy band + mark + one line ("Phần mềm diệt virus
  miễn phí, nhẹ, làm giúp bạn"), three download buttons (Windows / macOS / Linux) from GitHub Releases,
  then three real screenshots, FAQ, privacy, terms, changelog link.
- **Store / release screenshots**: the light theme, 1280×800, one message per image, captions in Be Vietnam Pro.
- **Release notes**: from CHANGELOG.md; Vietnamese first; what changed for the user, then technical notes.
- **Social cards / video thumbnails**: navy background, the ☶ pattern on the right, one line of text, the mark bottom-left.
