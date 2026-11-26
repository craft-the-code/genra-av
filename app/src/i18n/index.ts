import vi from "./vi.json";
import en from "./en.json";

export type Lang = "vi" | "en";
export type Key = keyof typeof vi;
const tables: Record<Lang, Record<string, string>> = { vi, en };

let lang: Lang = "vi";

export function setLang(l: Lang) {
  lang = l;
  document.documentElement.lang = l;
}
export const getLang = () => lang;

/** Looks up a string; `{name}` placeholders are filled from `vars`. Falls back to Vietnamese. */
export function t(key: Key | string, vars: Record<string, string | number> = {}): string {
  const s = tables[lang][key] ?? tables.vi[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (_, k) => String(vars[k] ?? `{${k}}`));
}
