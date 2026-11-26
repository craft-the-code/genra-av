// Status icons: always shown next to a word (tokens.md: never colour alone), so they are aria-hidden.
export type Tone = "ok" | "warn" | "bad" | "soon";

const fill: Record<Tone, string> = {
  ok: "var(--icon-ok)",
  warn: "var(--icon-warn)",
  bad: "var(--icon-bad)",
  soon: "var(--icon-neutral)",
};

const glyph: Record<Tone, string> = {
  ok: '<path d="M15 26 l8 8 l15 -17" stroke="#fff" stroke-width="5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  warn: '<rect x="23.5" y="13" width="5" height="16" rx="2.5" fill="#0F1115"/><circle cx="26" cy="36" r="3" fill="#0F1115"/>',
  bad: '<path d="M17 17 L35 35 M35 17 L17 35" stroke="#fff" stroke-width="5" stroke-linecap="round"/>',
  soon: '<path d="M17 26 H35" stroke="#fff" stroke-width="5" stroke-linecap="round"/>',
};

export function icon(tone: Tone): string {
  return `<svg class="icon" viewBox="0 0 52 52" aria-hidden="true" focusable="false"><circle cx="26" cy="26" r="26" fill="${fill[tone]}"/>${glyph[tone]}</svg>`;
}

/** The ☶ mark (assets/brand/mark.svg); graphite in light, silver in dark. */
export const mark = `<svg viewBox="96 88 320 380" aria-hidden="true" focusable="false"><defs><linearGradient id="mk" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--mark-top)"/><stop offset=".55" stop-color="var(--mark-mid)"/><stop offset="1" stop-color="var(--mark-bottom)"/></linearGradient></defs><g fill="url(#mk)"><path d="M112 120 Q112 104 128 104 H384 Q400 104 400 120 V178 H112 Z"/><path d="M112 216 H232 V290 H118 Q112 290 112 280 Z"/><path d="M280 216 H400 V280 Q400 290 394 290 H280 Z"/><path d="M116 328 H232 V452 Q156 420 124 356 Z"/><path d="M280 328 H396 L388 356 Q356 420 280 452 Z"/></g></svg>`;
