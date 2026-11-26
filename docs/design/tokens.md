# Genra AV design tokens (v0, 26/11/2026)

Small on purpose: the pattern of the top AV brands (graphite surfaces, one accent, status colours
that mean one thing each), with Genra's own ☶ mark. **Light is the default theme** (Hoan, 26/11:
office PCs and the apps officers use all day are light; most AV vendors default to light). Dark is
offered and follows the OS setting when the user picks "Theo hệ thống".
Mock-ups: `docs/ux/mocks/v1/` (light and dark).

## Colour roles

Each colour has one meaning. **Primary is never used for status, status colours are never used for actions.**

| Role | Light (default) | Dark | Use |
|---|---|---|---|
| `bg` | `#F6F7F9` | `#0F1115` | Window background |
| `surface` | `#FFFFFF` | `#171A21` | Cards |
| `surface-2` | `#EEF0F3` | `#1F232C` | Selected nav item, inputs |
| `border` | `#E3E6EB` | `#2A2F3A` | Card and divider lines |
| `text` | `#12151B` | `#F2F4F7` | Main text |
| `text-muted` | `#5B6270` | `#A3AAB8` | Secondary text |
| `primary` | `#2F6BEF` | `#2F6BEF` | Buttons, focus ring, selected marker (Genra Lam) |
| `primary-text` | `#2F6BEF` | `#6E9BFF` | Links and text actions |
| `success` | `#11804F` | `#2EBD85` | "An toàn", done |
| `warning` | `#97590A` | `#F5A524` | Needs a look (suspicious, Defender off) |
| `danger` | `#C62F35` | `#D93A40` | Malware only |

Icons may use the brighter `#16935F` / `#F5A524` fills (with a white / dark glyph); text uses the tokens above.
| `mark` | graphite `#3A3F4A → #15171C` | silver `#FFFFFF → #DADDE3 → #A9AFBA` | The ☶ mark, nothing else |

Why blue (Hoan, 26/11): yellow and red already mean warning and danger, so an accent in either
blurs "press here" with "be careful". Blue carries no status meaning and reads as trustworthy.
Five-element story still holds: the silver mark is Metal, the blue UI is Water; Metal gives birth to Water.

### Contrast (WCAG 2.1, checked 26/11)

| Pair | Light (default) | Dark |
|---|---|---|
| White on `primary` (buttons) | 4.70 (AA) | 4.70 (AA) |
| `primary-text` on `surface` (links) | 4.70 (AA) | 6.46 |
| `text-muted` on `surface` | 6.13 | 7.46 |
| `success` text on `surface` / `bg` | 4.97 / 4.64 (AA) | 7.24 |
| `warning` text on `surface` / `bg` | 5.60 / 5.23 (AA) | n/a (warning chips use dark text on `#F5A524`: 9.26) |
| White on `danger` | 5.44 | 4.54 (AA) |

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
