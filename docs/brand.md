# Genra AV: name and mark

## Name

**Genra** comes from **Cấn ☶** (Gen, 艮), the Mountain trigram of the I Ching: stillness, *stopping*.
In feng shui Cấn sits in the north-east, the **Quỷ Môn** (demon gate) where bad influence enters,
and it is the trigram that guards that gate. An antivirus does the same job: it stops what should
not come in, at the door. "AV" is added so nobody has to guess what the product is.

The name is meant to work without the story: two syllables, the same in Vietnamese and English.

Checked 26/11/2026: no security product or trademark named "Genra" found in web and trademark
searches; nearest marks are GENRAE (app software, US, Generational Equity Labs) and GENERRA
(advertising). GenRA is also a US EPA toxicology tool (different field). `genra.com` is parked for
sale; `genraav.com` and `genra-av.com` were unregistered; crates.io has no `genra`/`genra-av`.
Still to check before launch: Vietnam IP Office (NOIP) and WIPO Global Brand Database, class 9 and 42.

## Mark

The shield is the trigram ☶ itself: the solid top line (yang) is the roof of the mountain, the two
broken lines (yin) below are the gate, and the lowest line narrows into the point of the shield.
The slit down the middle is the gate that only lets clean files through.

## Colour

Five-element story: Cấn is **Earth**; Earth gives birth to **Metal**, so the mark is metal:
silver gradient `#FFFFFF → #DADDE3 → #A9AFBA` on graphite `#23262E → #121418`; on light grounds
the mark is graphite `#3A3F4A → #15171C`. The launch years 2026–2027 (Bính Ngọ, Đinh Mùi) are
*Thiên Hà Thủy* (Water), and Metal gives birth to Water: name → colour → year is one generating chain.
Red (Fire, which melts Metal) is used only for alarms: `#E5484D`.

The app UI (26/11) is graphite with one blue accent, Genra Lam `#2F6BEF` (Water: the Metal mark
gives birth to the Water UI). Yellow and red stay reserved for warning and danger. Full tokens:
[design/tokens.md](design/tokens.md).

## Files (`assets/brand`)

| File | Use |
|---|---|
| `app-icon.svg`, `png/app-icon-*.png` | App and installer icon, 16–1024 px |
| `mark.svg` / `mark-on-dark.svg` | Mark alone on light / dark grounds |
| `logo-light.svg` / `logo-dark.svg` | Mark + wordmark |
| `tray.svg`, `tray-alert.svg` | Tray / menu-bar icon (`currentColor`), alert adds the red dot |

The wordmark uses live text (Avenir Next, falling back to Montserrat/Inter). Convert it to paths
before printing or shipping an installer, so it does not change with the viewer's fonts.
