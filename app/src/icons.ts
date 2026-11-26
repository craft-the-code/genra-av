// Icons. Line icons are Lucide (https://lucide.dev, ISC licence, see NOTICE), drawn at 20 px with
// a 1.75 px stroke (brand-system §4). Status icons are filled circles with a glyph and always sit
// next to a word (tokens.md: never colour alone), so every icon here is aria-hidden.
export type Tone = "ok" | "warn" | "bad" | "soon";

const fill: Record<Tone, string> = {
  ok: "var(--icon-ok)",
  warn: "var(--icon-warn)",
  bad: "var(--icon-bad)",
  soon: "var(--icon-neutral)",
};

const glyph: Record<Tone, string> = {
  ok: '<path d="M15 26 l8 8 l15 -17" stroke="#fff" stroke-width="5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  warn: '<rect x="23.5" y="13" width="5" height="16" rx="2.5" fill="#1A1300"/><circle cx="26" cy="36" r="3" fill="#1A1300"/>',
  bad: '<path d="M17 17 L35 35 M35 17 L17 35" stroke="#fff" stroke-width="5" stroke-linecap="round"/>',
  soon: '<path d="M17 26 H35" stroke="#fff" stroke-width="5" stroke-linecap="round"/>',
};

export function icon(tone: Tone): string {
  return `<svg class="icon" viewBox="0 0 52 52" aria-hidden="true" focusable="false"><circle cx="26" cy="26" r="26" fill="${fill[tone]}"/>${glyph[tone]}</svg>`;
}

// Lucide path data (ISC). Names follow lucide.dev.
const LUCIDE: Record<string, string> = {
  house:
    '<path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 .709-1.528l7-5.999a2 2 0 0 1 2.582 0l7 5.999A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  "file-check":
    '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="m9 15 2 2 4-4"/>',
  monitor: '<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
  "sliders-horizontal":
    '<line x1="21" x2="14" y1="4" y2="4"/><line x1="10" x2="3" y1="4" y2="4"/><line x1="21" x2="12" y1="12" y2="12"/><line x1="8" x2="3" y1="12" y2="12"/><line x1="21" x2="16" y1="20" y2="20"/><line x1="12" x2="3" y1="20" y2="20"/><line x1="14" x2="14" y1="2" y2="6"/><line x1="8" x2="8" y1="10" y2="14"/><line x1="16" x2="16" y1="18" y2="22"/>',
  "undo-2": '<path d="M9 14 4 9l5-5"/><path d="M4 9h10.5a5.5 5.5 0 0 1 5.5 5.5a5.5 5.5 0 0 1-5.5 5.5H11"/>',
  shield:
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
  "refresh-cw":
    '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
  "chevron-right": '<path d="m9 18 6-6-6-6"/>',
  folder:
    '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
  "message-square": '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
  "hard-drive":
    '<line x1="22" x2="2" y1="12" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" x2="6.01" y1="16" y2="16"/><line x1="10" x2="10.01" y1="16" y2="16"/>',
  lock: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  "external-link":
    '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
};

export function line(name: keyof typeof LUCIDE | string, size = 20): string {
  return `<svg class="lucide" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${LUCIDE[name] ?? ""}</svg>`;
}

/** The ☶ mark (assets/brand/mark.svg); silver on the navy sidebar. */
export const mark = `<svg viewBox="96 88 320 380" aria-hidden="true" focusable="false"><defs><linearGradient id="mk" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FFFFFF"/><stop offset=".55" stop-color="#DADDE3"/><stop offset="1" stop-color="#A9AFBA"/></linearGradient></defs><g fill="url(#mk)"><path d="M112 120 Q112 104 128 104 H384 Q400 104 400 120 V178 H112 Z"/><path d="M112 216 H232 V290 H118 Q112 290 112 280 Z"/><path d="M280 216 H400 V280 Q400 290 394 290 H280 Z"/><path d="M116 328 H232 V452 Q156 420 124 356 Z"/><path d="M280 328 H396 L388 356 Q356 420 280 452 Z"/></g></svg>`;

/** The ☶ line motif for the brand band: one solid bar over two broken ones, white at ≤ 8 %. */
export const trigramPattern = `<svg class="motif" aria-hidden="true" focusable="false"><defs><pattern id="tri" width="72" height="108" patternUnits="userSpaceOnUse"><g fill="#fff">
<rect x="12" y="10" width="48" height="8" rx="4"/><rect x="12" y="24" width="20" height="8" rx="4"/><rect x="40" y="24" width="20" height="8" rx="4"/><rect x="12" y="38" width="20" height="8" rx="4"/><rect x="40" y="38" width="20" height="8" rx="4"/>
<rect x="-24" y="64" width="48" height="8" rx="4"/><rect x="-24" y="78" width="20" height="8" rx="4"/><rect x="4" y="78" width="20" height="8" rx="4"/><rect x="-24" y="92" width="20" height="8" rx="4"/><rect x="4" y="92" width="20" height="8" rx="4"/>
<rect x="48" y="64" width="48" height="8" rx="4"/><rect x="48" y="78" width="20" height="8" rx="4"/><rect x="76" y="78" width="20" height="8" rx="4"/><rect x="48" y="92" width="20" height="8" rx="4"/><rect x="76" y="92" width="20" height="8" rx="4"/>
</g></pattern></defs><rect width="100%" height="100%" fill="url(#tri)"/></svg>`;
