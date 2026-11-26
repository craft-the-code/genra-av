-- Genra AV backend schema. No raw IPs, no document content: see docs/release-plan.md (privacy).

CREATE TABLE IF NOT EXISTS reports (
  id          TEXT PRIMARY KEY,
  created_at  TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('false_positive', 'missed_threat', 'bug', 'other')),
  app_version TEXT NOT NULL,
  os          TEXT NOT NULL,
  install_id  TEXT NOT NULL,
  ip_hash     TEXT NOT NULL,
  sha256      TEXT,
  rule_id     TEXT,
  note        TEXT,
  email       TEXT
);
CREATE INDEX IF NOT EXISTS reports_install ON reports (install_id, created_at);
CREATE INDEX IF NOT EXISTS reports_ip ON reports (ip_hash, created_at);
CREATE INDEX IF NOT EXISTS reports_created ON reports (created_at);

CREATE TABLE IF NOT EXISTS samples (
  id          TEXT PRIMARY KEY,
  created_at  TEXT NOT NULL,
  body_sha256 TEXT NOT NULL UNIQUE,
  doc_sha256  TEXT NOT NULL,
  size        INTEGER NOT NULL,
  app_version TEXT NOT NULL,
  os          TEXT NOT NULL,
  install_id  TEXT NOT NULL,
  ip_hash     TEXT NOT NULL,
  rule_id     TEXT,
  r2_key      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS samples_install ON samples (install_id, created_at);
CREATE INDEX IF NOT EXISTS samples_ip ON samples (ip_hash, created_at);
CREATE INDEX IF NOT EXISTS samples_created ON samples (created_at);
