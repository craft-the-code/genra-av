// Genra AV backend: one Cloudflare Worker, D1 for rows, R2 for VBA samples.
//   GET  /v1/health   liveness
//   POST /v1/report   false positive / missed threat / bug report (JSON)
//   POST /v1/sample   extracted VBA project for analysis (raw body, metadata in headers)
//   GET  /v1/lookup/<5 hex>  known-bad SHA-256 starting with that prefix (k-anonymity, ADR 0004 step 5)
// No accounts and no cookies. Raw IPs are never stored: only a daily-salted hash for rate limits.

import { checkSampleBody, parsePrefix, parseReport, parseSampleMeta } from "./validate.ts";

export interface Env {
  DB: D1Database;
  SAMPLES: R2Bucket;
  IP_SALT?: string;
  RETENTION_DAYS?: string;
}

const VERSION = "0.1.0";
const LIMITS = { report: 30, sample: 10 }; // per install and per IP hash, rolling 24 h

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers":
    "content-type, x-genra-consent, x-genra-version, x-genra-os, x-genra-install, x-genra-doc-sha256, x-genra-rule",
  "access-control-max-age": "86400",
};

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", ...CORS } });

async function sha256Hex(data: ArrayBuffer | Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function ipHash(req: Request, env: Env): Promise<string> {
  const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
  const day = new Date().toISOString().slice(0, 10);
  return (await sha256Hex(`${env.IP_SALT ?? "dev-salt"}|${day}|${ip}`)).slice(0, 32);
}

async function overLimit(env: Env, table: "reports" | "samples", installId: string, ip: string, max: number) {
  const since = new Date(Date.now() - 86400e3).toISOString();
  const row = await env.DB.prepare(
    `SELECT (SELECT COUNT(*) FROM ${table} WHERE install_id = ?1 AND created_at > ?3) AS by_install,
            (SELECT COUNT(*) FROM ${table} WHERE ip_hash = ?2 AND created_at > ?3) AS by_ip`,
  )
    .bind(installId, ip, since)
    .first<{ by_install: number; by_ip: number }>();
  return (row?.by_install ?? 0) >= max || (row?.by_ip ?? 0) >= max;
}

async function handleReport(req: Request, env: Env): Promise<Response> {
  if (!(req.headers.get("content-type") ?? "").includes("application/json")) return json(415, { error: "send JSON" });
  const text = await req.text();
  if (text.length > 16_384) return json(413, { error: "body too large" });
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return json(400, { error: "invalid JSON" });
  }
  const parsed = parseReport(body);
  if (!parsed.ok) return json(400, { error: parsed.error });
  const r = parsed.value;
  const ip = await ipHash(req, env);
  if (await overLimit(env, "reports", r.install_id, ip, LIMITS.report)) return json(429, { error: "too many reports today" });
  const id = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO reports (id, created_at, kind, app_version, os, install_id, ip_hash, sha256, rule_id, note, email)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
  )
    .bind(id, new Date().toISOString(), r.kind, r.app_version, r.os, r.install_id, ip, r.sha256, r.rule_id, r.note, r.email)
    .run();
  return json(201, { id });
}

async function handleSample(req: Request, env: Env): Promise<Response> {
  const meta = parseSampleMeta(req.headers);
  if (!meta.ok) return json(400, { error: meta.error });
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > 1024 * 1024) return json(413, { error: "sample too large" });
  const body = new Uint8Array(await req.arrayBuffer());
  const checked = checkSampleBody(body);
  if (!checked.ok) return json(400, { error: checked.error });
  const m = meta.value;
  const ip = await ipHash(req, env);
  if (await overLimit(env, "samples", m.install_id, ip, LIMITS.sample)) return json(429, { error: "too many samples today" });
  const bodySha = await sha256Hex(body);
  const now = new Date();
  const key = `samples/${now.toISOString().slice(0, 7)}/${bodySha}.vba`;
  const existing = await env.DB.prepare("SELECT id FROM samples WHERE body_sha256 = ?1").bind(bodySha).first<{ id: string }>();
  if (existing) return json(200, { id: existing.id, duplicate: true });
  await env.SAMPLES.put(key, body, {
    httpMetadata: { contentType: "application/octet-stream" },
    customMetadata: { doc_sha256: m.doc_sha256, app_version: m.app_version, os: m.os, rule_id: m.rule_id ?? "" },
  });
  const id = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO samples (id, created_at, body_sha256, doc_sha256, size, app_version, os, install_id, ip_hash, rule_id, r2_key)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
  )
    .bind(id, now.toISOString(), bodySha, m.doc_sha256, body.byteLength, m.app_version, m.os, m.install_id, ip, m.rule_id, key)
    .run();
  return json(201, { id, duplicate: false });
}

/** Every known-bad hash with this prefix; the client compares its full hash on the machine. The
 *  answer is the same for everyone, so Cloudflare's cache serves repeats and nothing about the
 *  asker is stored: no row is written, no IP is kept (ADR 0004: no request log of prefixes or IPs). */
async function handleLookup(req: Request, raw: string, env: Env, ctx: ExecutionContext): Promise<Response> {
  const p = parsePrefix(raw);
  if (!p.ok) return json(400, { error: p.error });
  // The Worker runs in front of Cloudflare's cache, so it keeps answers there itself.
  const key = new Request(new URL(`/v1/lookup/${p.value}`, req.url).toString());
  const hit = await caches.default.match(key);
  if (hit) return hit;
  const rows = await env.DB.prepare("SELECT sha256 FROM known_bad WHERE prefix = ?1 ORDER BY sha256 LIMIT 2000")
    .bind(p.value)
    .all<{ sha256: string }>();
  const res = json(200, { prefix: p.value, hashes: rows.results.map((r) => r.sha256) });
  res.headers.set("cache-control", "public, max-age=3600");
  ctx.waitUntil(caches.default.put(key, res.clone()));
  return res;
}

/** Daily: delete samples and rows past the retention promised in the privacy policy. */
async function purge(env: Env): Promise<void> {
  const days = Number(env.RETENTION_DAYS ?? "90");
  const cutoff = new Date(Date.now() - days * 86400e3).toISOString();
  const old = await env.DB.prepare("SELECT id, r2_key FROM samples WHERE created_at < ?1 LIMIT 500").bind(cutoff).all<{ id: string; r2_key: string }>();
  if (old.results.length) {
    await env.SAMPLES.delete(old.results.map((r) => r.r2_key));
    await env.DB.batch(old.results.map((r) => env.DB.prepare("DELETE FROM samples WHERE id = ?1").bind(r.id)));
  }
  await env.DB.prepare("DELETE FROM reports WHERE created_at < ?1").bind(cutoff).run();
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    try {
      if (url.pathname === "/v1/health" && req.method === "GET") return json(200, { ok: true, service: "genra-api", version: VERSION });
      if (url.pathname === "/v1/report" && req.method === "POST") return await handleReport(req, env);
      if (url.pathname === "/v1/sample" && req.method === "POST") return await handleSample(req, env);
      if (url.pathname.startsWith("/v1/lookup/") && req.method === "GET") return await handleLookup(req, url.pathname.slice("/v1/lookup/".length), env, ctx);
      return json(404, { error: "not found" });
    } catch (e) {
      console.error("unhandled", e instanceof Error ? e.message : String(e));
      return json(500, { error: "internal error" });
    }
  },
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(purge(env));
  },
} satisfies ExportedHandler<Env>;
