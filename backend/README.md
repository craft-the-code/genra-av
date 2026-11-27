# Genra AV backend

One Cloudflare Worker (`genra-api`) with D1 (rows) and R2 (samples). Public on purpose: anyone can
read exactly what Genra AV collects. No secrets live in this folder; the IP salt is a Worker secret.

| Endpoint | What it takes | Stored |
|---|---|---|
| `GET /v1/health` | nothing | nothing |
| `POST /v1/report` | JSON: `kind` (`false_positive`, `missed_threat`, `bug`, `other`), `app_version`, `os`, `install_id` (random UUID per install), optional `sha256` of the file, `rule_id`, `note` (≤ 2000 chars), `email` | the row, plus a daily-salted hash of the IP for rate limiting |
| `GET /v1/lookup/<prefix>` | the first 5 hex characters of a file's SHA-256 (ADR 0004 step 5) | nothing: no row, no IP hash; the answer (every known-bad hash with that prefix) is the same for everyone and cached by Cloudflare for an hour |
| `POST /v1/sample` | raw body = **the VBA project the app extracted** (OLE2, ≤ 1 MB, never the whole document); headers `x-genra-consent: yes`, `x-genra-version`, `x-genra-os`, `x-genra-install`, `x-genra-doc-sha256`, optional `x-genra-rule` | the VBA project in R2, metadata row in D1 |

Limits: 30 reports and 10 samples per install and per IP hash per 24 h. Retention: 90 days, purged
daily by the cron trigger (`RETENTION_DAYS`).

## Develop

```bash
npm install
npm test                    # input validation (node:test)
npm run migrate:local       # local D1 schema
npm run dev                 # http://localhost:8787
```

## Deploy

```bash
npx wrangler d1 create genra                 # put the id into wrangler.toml
npx wrangler r2 bucket create genra-samples
npx wrangler d1 migrations apply genra --remote
npx wrangler secret put IP_SALT              # any long random string
npx wrangler deploy                          # serves https://genra-api.craftthecode.dev
```

## Known-bad hashes for the lookup

The app asks `/v1/lookup/<prefix>` only in builds where `lookup::AVAILABLE` is true, which ships
with the privacy policy change (docs/legal/online-lookup.md). The `known_bad` table (migration 0002)
holds public feed hashes, never anything from users. Load or refresh it from a hash list:

```bash
npx wrangler d1 migrations apply genra --remote
./target/release/genra-av hashes dump feeds-<v>.bin > feeds.txt     # from a signed pack
python3 scripts/known-bad-sql.py malwarebazaar feeds.txt > load.sql
npx wrangler d1 execute genra --remote --file load.sql
```

Loading again is harmless (`INSERT OR IGNORE`). Workers Logs (`[observability]`) records each
request's URL, which contains the prefix: turn observability off or sample it down before the lookup
goes live, since ADR 0004 promises no log of prefixes beyond rate limiting.
