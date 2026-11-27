-- Known-bad file hashes for the online lookup by hash prefix (ADR 0004, step 5). Hashes only:
-- public feed data, nothing from users. Loaded by scripts/known-bad-sql.py (docs in backend/README.md).
CREATE TABLE IF NOT EXISTS known_bad (
  sha256   TEXT PRIMARY KEY CHECK (length(sha256) = 64),
  prefix   TEXT NOT NULL CHECK (length(prefix) = 5),
  source   TEXT NOT NULL,
  added_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS known_bad_prefix ON known_bad (prefix);
