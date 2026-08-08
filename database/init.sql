-- ═══════════════════════════════════════════════════════════════════════════
--  Aegis Sandbox AI — database schema (PostgreSQL)
--  Auto-loaded by the db container on first start.
--  This is the production data model; the prototype backend can also run on
--  SQLite with SQLAlchemy without this file.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Analysts / users ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analysts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT UNIQUE NOT NULL,
    full_name   TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'soc_analyst',   -- soc_analyst | malware_analyst | threat_hunter | ir | soc_manager
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Samples ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS samples (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename      TEXT NOT NULL,
    file_type     TEXT NOT NULL,                       -- exe | dll | pdf | docx | zip | iso
    size_bytes    BIGINT NOT NULL,
    sha256        TEXT UNIQUE NOT NULL,
    md5           TEXT NOT NULL,
    sha1          TEXT NOT NULL,
    submitted_by  UUID REFERENCES analysts(id),
    submitted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples(sha256);

-- ── Investigations ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS investigations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         TEXT UNIQUE NOT NULL,              -- AGS-2026-0412
    sample_id       UUID NOT NULL REFERENCES samples(id),
    status          TEXT NOT NULL DEFAULT 'queued',    -- queued | running | analysing | ai-processing | completed | failed
    progress        INT NOT NULL DEFAULT 0,
    severity        TEXT,                              -- critical | high | medium | low | info | clean
    risk_score      INT,
    malware_family  TEXT,
    classification  TEXT,
    verdict         TEXT,                              -- malicious | suspicious | clean
    ai_confidence   INT,
    detections      INT DEFAULT 0,
    total_engines   INT DEFAULT 0,
    assigned_to     UUID REFERENCES analysts(id),
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_severity ON investigations(severity);

-- ── Analysis artefacts (static / dynamic / network / ai) ────────────────────
-- Stored as JSONB so the schema flexes with evolving analyzer output.
CREATE TABLE IF NOT EXISTS analysis_results (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id  UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    kind              TEXT NOT NULL,                   -- static | dynamic | network | threat_intel | mitre | ai
    payload           JSONB NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_analysis_inv ON analysis_results(investigation_id, kind);

-- ── Indicators of Compromise ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id  UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    ioc_type          TEXT NOT NULL,                   -- hash | ip | domain | url | mutex | registry | filename
    value             TEXT NOT NULL,
    context           TEXT,
    severity          TEXT
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);

-- ── MITRE technique mappings ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mitre_mappings (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id  UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    technique_id      TEXT NOT NULL,                   -- T1055
    technique_name    TEXT NOT NULL,
    tactic            TEXT NOT NULL,
    severity          TEXT,
    evidence          TEXT
);

-- ── Seed a demo analyst ────────────────────────────────────────────────────
INSERT INTO analysts (email, full_name, role)
VALUES ('j.okafor@aegis-soc.io', 'J. Okafor', 'soc_analyst')
ON CONFLICT (email) DO NOTHING;
