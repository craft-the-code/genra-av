# Genra AV design tokens (v0, 26/11/2026)

Small on purpose: the pattern of the top AV brands (graphite surfaces, one accent, status colours
that mean one thing each), with Genra's own silver ☶ mark. Dark is the default theme; light mirrors it.
Mock-ups: `docs/ux/` (to be added with the screen mock-ups).

## Colour roles

Each colour has one meaning. **Primary is never used for status, status colours are never used for actions.**

| Role | Dark | Light | Use |
|---|---|---|---|
| `bg` | `#0F1115` | `#F6F7F9` | Window background |
| `surface` | `#171A21` | `#FFFFFF` | Cards |
| `surface-2` | `#1F232C` | `#EEF0F3` | Selected nav item, inputs |
| `border` | `#2A2F3A` | `#E3E6EB` | Card and divider lines |
| `text` | `#F2F4F7` | `#12151B` | Main text |
| `text-muted` | `#A3AAB8` | `#5B6270` | Secondary text |
| `primary` | `#2F6BEF` | `#2F6BEF` | Buttons, focus ring, selected marker (Genra Lam) |
| `primary-text` | `#6E9BFF` | `#2F6BEF` | Links and text actions |
| `success` | `#2EBD85` | `#16935F` | "An toàn", done |
| `warning` | `#F5A524` | `#B26A00` | Needs a look (suspicious, Defender off) |
| `danger` | `#D93A40` | `#C62F35` | Malware only |
| `mark` | silver `#FFFFFF → #DADDE3 → #A9AFBA` | graphite `#3A3F4A → #15171C` | The ☶ mark, nothing else |

Why blue (Hoan, 26/11): yellow and red already mean warning and danger, so an accent in either
blurs "press here" with "be careful". Blue carries no status meaning and reads as trustworthy.
Five-element story still holds: the silver mark is Metal, the blue UI is Water; Metal gives birth to Water.

### Contrast (WCAG 2.1, checked 26/11)

| Pair | Ratio |
|---|---|
| White on `primary` | 4.70 (AA) |
| `primary-text` on dark `bg` / `surface` | 7.01 / 6.46 |
| `primary` on white | 4.70 (AA) |
| `text-muted` on dark `surface` / on white | 7.46 / 6.13 |
| White on `danger` | 4.54 (AA) |
| `success` on dark `surface` | 7.24 |
| Dark text on `warning` | 9.26 (warning chips use dark text, never white) |

## Type

System fonts, no web fonts to download: Segoe UI Variable (Windows), SF Pro (macOS), Inter fallback.
Full Vietnamese diacritics are covered by all three.

| Token | Size / line | Weight | Use |
|---|---|---|---|
| `title` | 24 / 32 | 700 | Screen title, status ("Máy an toàn") |
| `heading` | 17 / 24 | 700 | Card titles, finding names |
| `body` | 14 / 20 | 400 | Text |
| `caption` | 12 / 16 | 400 | Times, counts, hints |
| `overline` | 11 / 16 | 700, +1 tracking, caps | Section labels ("GẦN ĐÂY") |

Body never below 14 px: the first users read on old monitors at arm's length.

## Shape and space

- Spacing scale: 4, 8, 12, 16, 24, 32, 48.
- Radius: 8 (buttons, inputs, nav item), 12 (cards), 16 (hero status card).
- Buttons: 40 px tall (32 compact), 16 px side padding; one primary button per screen.
- Status always pairs colour with an icon and a word (✓ An toàn, ! Cần xem, ✕ Mã độc), never colour alone.
- Motion: 150–200 ms ease-out; respect "reduce motion".
