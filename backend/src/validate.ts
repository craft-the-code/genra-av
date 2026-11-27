// Input checks for the public API. Everything a client sends is untrusted: fields are typed,
// length-capped and enumerated here, before anything reaches D1 or R2.

export const REPORT_KINDS = ["false_positive", "missed_threat", "bug", "other"] as const;
export const OSES = ["windows", "macos", "linux", "web"] as const;
export const MAX_NOTE = 2000;
export const MAX_SAMPLE_BYTES = 1024 * 1024;
const OLE_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

export type Report = {
  kind: (typeof REPORT_KINDS)[number];
  app_version: string;
  os: (typeof OSES)[number];
  install_id: string;
  sha256: string | null;
  rule_id: string | null;
  note: string | null;
  email: string | null;
};

export type SampleMeta = {
  app_version: string;
  os: (typeof OSES)[number];
  install_id: string;
  doc_sha256: string;
  rule_id: string | null;
};

type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export const isSha256 = (s: unknown): s is string => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
export const isUuid = (s: unknown): s is string =>
  typeof s === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s);
export const isVersion = (s: unknown): s is string =>
  typeof s === "string" && s.length <= 32 && /^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/.test(s);
const isRuleId = (s: unknown): s is string => typeof s === "string" && /^[A-Za-z0-9._-]{1,80}$/.test(s);
const isEmail = (s: unknown): s is string =>
  typeof s === "string" && s.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const oneOf = <T extends readonly string[]>(list: T, s: unknown): s is T[number] =>
  typeof s === "string" && (list as readonly string[]).includes(s);

function optional<T>(v: unknown, check: (x: unknown) => x is T, name: string): Result<T | null> {
  if (v === undefined || v === null || v === "") return { ok: true, value: null };
  return check(v) ? { ok: true, value: v } : { ok: false, error: `invalid ${name}` };
}

export function parseReport(body: unknown): Result<Report> {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return { ok: false, error: "body must be a JSON object" };
  const b = body as Record<string, unknown>;
  if (!oneOf(REPORT_KINDS, b.kind)) return { ok: false, error: "invalid kind" };
  if (!isVersion(b.app_version)) return { ok: false, error: "invalid app_version" };
  if (!oneOf(OSES, b.os)) return { ok: false, error: "invalid os" };
  if (!isUuid(b.install_id)) return { ok: false, error: "invalid install_id" };
  const sha = optional(b.sha256, isSha256, "sha256");
  const rule = optional(b.rule_id, isRuleId, "rule_id");
  const email = optional(b.email, isEmail, "email");
  for (const r of [sha, rule, email]) if (!r.ok) return r;
  let note: string | null = null;
  if (b.note !== undefined && b.note !== null) {
    if (typeof b.note !== "string") return { ok: false, error: "invalid note" };
    if (b.note.length > MAX_NOTE) return { ok: false, error: `note longer than ${MAX_NOTE} characters` };
    note = b.note.trim() || null;
  }
  if (b.kind === "false_positive" && !sha.ok) return sha;
  if (b.kind === "false_positive" && (sha as { value: string | null }).value === null)
    return { ok: false, error: "false_positive needs sha256" };
  return {
    ok: true,
    value: {
      kind: b.kind,
      app_version: b.app_version,
      os: b.os,
      install_id: b.install_id,
      sha256: (sha as { value: string | null }).value,
      rule_id: (rule as { value: string | null }).value,
      note,
      email: (email as { value: string | null }).value,
    },
  };
}

/** Sample metadata travels in headers so the body can be the raw VBA project. */
export function parseSampleMeta(h: Headers): Result<SampleMeta> {
  if (h.get("x-genra-consent") !== "yes") return { ok: false, error: "consent header missing" };
  const app_version = h.get("x-genra-version");
  const os = h.get("x-genra-os");
  const install_id = h.get("x-genra-install");
  const doc_sha256 = h.get("x-genra-doc-sha256");
  if (!isVersion(app_version)) return { ok: false, error: "invalid x-genra-version" };
  if (!oneOf(OSES, os)) return { ok: false, error: "invalid x-genra-os" };
  if (!isUuid(install_id)) return { ok: false, error: "invalid x-genra-install" };
  if (!isSha256(doc_sha256)) return { ok: false, error: "invalid x-genra-doc-sha256" };
  const rule = optional(h.get("x-genra-rule"), isRuleId, "x-genra-rule");
  if (!rule.ok) return rule;
  return { ok: true, value: { app_version, os, install_id, doc_sha256, rule_id: rule.value } };
}

/**
 * A sample must be a VBA project extracted by the app (an OLE2 compound file, like
 * vbaProject.bin), never the whole document: officers' files carry personal data, the macro
 * code does not. The app sends only that part; this check refuses anything else.
 */
export function checkSampleBody(bytes: Uint8Array): Result<Uint8Array> {
  if (bytes.byteLength === 0) return { ok: false, error: "empty body" };
  if (bytes.byteLength > MAX_SAMPLE_BYTES) return { ok: false, error: `sample larger than ${MAX_SAMPLE_BYTES} bytes` };
  if (!OLE_MAGIC.every((b, i) => bytes[i] === b)) return { ok: false, error: "sample must be an extracted VBA project (OLE2)" };
  return { ok: true, value: bytes };
}

/** The online lookup's prefix: exactly the first 5 hex characters of a SHA-256 (20 bits), lower case. */
export const PREFIX_LEN = 5;
export function parsePrefix(raw: string): Result<string> {
  const p = raw.toLowerCase();
  return /^[0-9a-f]{5}$/.test(p) ? { ok: true, value: p } : { ok: false, error: "prefix must be 5 hex characters" };
}
