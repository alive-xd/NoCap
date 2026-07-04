-- NoCap: Threat Intelligence Investigation Platform
-- Schema v1.0 — frozen architecture as per ADR

-- ─────────────────────────────────────────────
-- ENUMS
-- ─────────────────────────────────────────────

CREATE TYPE target_type AS ENUM ('IP', 'DOMAIN', 'URL', 'HASH');

CREATE TYPE investigation_status AS ENUM (
  'CREATED',
  'FETCHING_ARTIFACTS',
  'EXTRACTING_EVIDENCE',
  'RUNNING_ANALYZERS',
  'SCORING',
  'GENERATING_SUMMARY',
  'COMPLETED',
  'FAILED'
);

CREATE TYPE finding_status AS ENUM (
  'FLAGGED',
  'CONFIRMED',
  'CLEARED',
  'UNDER_REVIEW'
);

-- ─────────────────────────────────────────────
-- SCORING PROFILES (versioned — read-only after insert)
-- ─────────────────────────────────────────────

CREATE TABLE scoring_profiles (
  version        TEXT PRIMARY KEY,
  source_weights JSONB NOT NULL,
  reasoning      JSONB NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────
-- INVESTIGATIONS
-- ─────────────────────────────────────────────

CREATE TABLE investigations (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  case_number             TEXT NOT NULL UNIQUE,           -- NC-2026-00142
  target                  TEXT NOT NULL,
  target_type             target_type NOT NULL,
  status                  investigation_status NOT NULL DEFAULT 'CREATED',
  final_score             INTEGER,                        -- 0-100, nullable until COMPLETED
  scoring_profile_version TEXT REFERENCES scoring_profiles(version),
  failed_sources          JSONB NOT NULL DEFAULT '[]',    -- array of { source, reason }
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at            TIMESTAMPTZ                     -- nullable; enables duration metrics
);

CREATE INDEX investigations_user_id_idx ON investigations(user_id);
CREATE INDEX investigations_target_idx ON investigations(target);
CREATE INDEX investigations_status_idx ON investigations(status);
CREATE INDEX investigations_created_at_idx ON investigations(created_at DESC);

-- ─────────────────────────────────────────────
-- ARTIFACTS (raw API responses — immutable after insert)
-- ─────────────────────────────────────────────

CREATE TABLE artifacts (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  source           TEXT NOT NULL,                        -- 'virustotal', 'abuseipdb', etc.
  raw_response     JSONB NOT NULL,
  fetched_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_reused        BOOLEAN NOT NULL DEFAULT FALSE        -- true = served from prior fresh artifact
);

CREATE INDEX artifacts_investigation_id_idx ON artifacts(investigation_id);
CREATE INDEX artifacts_source_idx ON artifacts(source);
CREATE INDEX artifacts_fetched_at_idx ON artifacts(fetched_at DESC);

-- ─────────────────────────────────────────────
-- EVIDENCE (atomic facts — no judgment applied)
-- ─────────────────────────────────────────────

CREATE TABLE evidence (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id    UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  fact_type      TEXT NOT NULL,                          -- e.g. 'malicious_count', 'entropy_score'
  fact_value     JSONB NOT NULL,                         -- flexible value storage
  parser_name    TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX evidence_artifact_id_idx ON evidence(artifact_id);
CREATE INDEX evidence_fact_type_idx ON evidence(fact_type);
CREATE INDEX evidence_parser_name_idx ON evidence(parser_name);

-- ─────────────────────────────────────────────
-- FINDINGS (scored claims backed by evidence)
-- ─────────────────────────────────────────────

CREATE TABLE findings (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id  UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  claim             TEXT NOT NULL,                       -- e.g. 'Multiple Vendor Consensus'
  severity          TEXT NOT NULL,                       -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
  confidence_score  INTEGER NOT NULL CHECK (confidence_score BETWEEN 0 AND 100),
  score_contribution INTEGER NOT NULL DEFAULT 0,
  status            finding_status NOT NULL DEFAULT 'FLAGGED',
  generated_by      TEXT NOT NULL,                       -- analyzer name
  analyzer_version  TEXT NOT NULL,
  reasoning         TEXT,                                -- human-readable explanation
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX findings_investigation_id_idx ON findings(investigation_id);
CREATE INDEX findings_generated_by_idx ON findings(generated_by);
CREATE INDEX findings_severity_idx ON findings(severity);

-- ─────────────────────────────────────────────
-- FINDING ↔ EVIDENCE (many-to-many junction)
-- ─────────────────────────────────────────────

CREATE TABLE finding_evidence (
  finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  evidence_id UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  PRIMARY KEY (finding_id, evidence_id)
);

CREATE INDEX finding_evidence_evidence_id_idx ON finding_evidence(evidence_id);

-- ─────────────────────────────────────────────
-- WATCHLIST (CVE Watch per-user targets)
-- ─────────────────────────────────────────────

CREATE TABLE watchlist (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target     TEXT NOT NULL,                              -- e.g. 'Microsoft/Exchange'
  module     TEXT NOT NULL DEFAULT 'cve_watch',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, target, module)
);

CREATE INDEX watchlist_user_id_idx ON watchlist(user_id);

-- ─────────────────────────────────────────────
-- INVESTIGATION METRICS (one row per investigation)
-- ─────────────────────────────────────────────

CREATE TABLE investigation_metrics (
  investigation_id   UUID PRIMARY KEY REFERENCES investigations(id) ON DELETE CASCADE,
  artifacts_fetched  INTEGER NOT NULL DEFAULT 0,
  evidence_extracted INTEGER NOT NULL DEFAULT 0,
  findings_generated INTEGER NOT NULL DEFAULT 0,
  failed_sources_count INTEGER NOT NULL DEFAULT 0,
  execution_time_ms  INTEGER NOT NULL DEFAULT 0
);

-- ─────────────────────────────────────────────
-- ANALYST NOTES (free-text, timestamped)
-- ─────────────────────────────────────────────

CREATE TABLE notes (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  content          TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX notes_investigation_id_idx ON notes(investigation_id);

-- ─────────────────────────────────────────────
-- INVESTIGATION TAGS (manual, user-applied)
-- ─────────────────────────────────────────────

CREATE TABLE tags (
  id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name    TEXT NOT NULL,
  UNIQUE(user_id, name)
);

CREATE TABLE investigation_tags (
  investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  tag_id           UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (investigation_id, tag_id)
);

-- ─────────────────────────────────────────────
-- ROW LEVEL SECURITY
-- ─────────────────────────────────────────────

ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_tags ENABLE ROW LEVEL SECURITY;

-- Investigations: users own their own rows
CREATE POLICY "Users own their investigations"
  ON investigations FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Artifacts: accessible if the parent investigation belongs to the user
CREATE POLICY "Users access their artifacts"
  ON artifacts FOR ALL
  USING (
    investigation_id IN (
      SELECT id FROM investigations WHERE user_id = auth.uid()
    )
  );

-- Evidence: accessible via artifact → investigation chain
CREATE POLICY "Users access their evidence"
  ON evidence FOR ALL
  USING (
    artifact_id IN (
      SELECT a.id FROM artifacts a
      JOIN investigations i ON i.id = a.investigation_id
      WHERE i.user_id = auth.uid()
    )
  );

-- Findings
CREATE POLICY "Users access their findings"
  ON findings FOR ALL
  USING (
    investigation_id IN (
      SELECT id FROM investigations WHERE user_id = auth.uid()
    )
  );

-- Finding evidence junction
CREATE POLICY "Users access their finding_evidence"
  ON finding_evidence FOR ALL
  USING (
    finding_id IN (
      SELECT f.id FROM findings f
      JOIN investigations i ON i.id = f.investigation_id
      WHERE i.user_id = auth.uid()
    )
  );

-- Watchlist
CREATE POLICY "Users own their watchlist"
  ON watchlist FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Metrics
CREATE POLICY "Users access their metrics"
  ON investigation_metrics FOR ALL
  USING (
    investigation_id IN (
      SELECT id FROM investigations WHERE user_id = auth.uid()
    )
  );

-- Notes
CREATE POLICY "Users access their notes"
  ON notes FOR ALL
  USING (
    investigation_id IN (
      SELECT id FROM investigations WHERE user_id = auth.uid()
    )
  )
  WITH CHECK (
    investigation_id IN (
      SELECT id FROM investigations WHERE user_id = auth.uid()
    )
  );

-- Tags
CREATE POLICY "Users own their tags"
  ON tags FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Investigation tags
CREATE POLICY "Users access their investigation_tags"
  ON investigation_tags FOR ALL
  USING (
    investigation_id IN (
      SELECT id FROM investigations WHERE user_id = auth.uid()
    )
  );
