// ─────────────────────────────────────────────────────────────────────────────
// NoCap Pipeline — Core Types (frozen architecture)
//
// Pipeline shape:
//   Artifact → Parser → Evidence → Analyzer → Finding → Score
//
// Every type here corresponds to a database table row.
// ─────────────────────────────────────────────────────────────────────────────

export type TargetType = "IP" | "DOMAIN" | "URL" | "HASH" | "CVE";

export type InvestigationStatus =
  | "CREATED"
  | "FETCHING_ARTIFACTS"
  | "EXTRACTING_EVIDENCE"
  | "RUNNING_ANALYZERS"
  | "SCORING"
  | "COMPLETED"
  | "FAILED";

export type FindingStatus = "FLAGGED" | "CONFIRMED" | "CLEARED" | "UNDER_REVIEW";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type ConfidenceLabel = "High" | "Medium" | "Low";

// ─── Database row types ───────────────────────────────────────────────────────

export interface Investigation {
  id: string;
  user_id: string;
  case_number: string;
  target: string;
  target_type: TargetType;
  status: InvestigationStatus;
  final_score: number | null;
  scoring_profile_version: string | null;
  failed_sources: FailedSource[];
  is_public_demo: boolean;

  created_at: string;
  completed_at: string | null;
}

export interface FailedSource {
  source: string;
  reason: string;
}

export interface Artifact {
  id: string;
  investigation_id: string;
  source: string;
  raw_response: Record<string, unknown>;
  fetched_at: string;
  is_reused: boolean;
}

export interface Evidence {
  id: string;
  artifact_id: string;
  fact_type: string;
  fact_value: unknown;
  parser_name: string;
  parser_version: string;
  created_at: string;
}

export interface Finding {
  id: string;
  investigation_id: string;
  claim: string;
  severity: Severity;
  confidence_score: number; // 0-100; source of truth
  score_contribution: number;
  status: FindingStatus;
  generated_by: string;
  analyzer_version: string;
  reasoning: string | null;
  created_at: string;
  // Joined relations (not stored as columns)
  evidence?: Evidence[];
  attack_techniques?: string[]; // MITRE ATT&CK technique IDs
}

export interface ScoringProfile {
  version: string;
  source_weights: Record<string, number>;
  reasoning: Record<string, string>;
  created_at: string;
}

export interface InvestigationMetrics {
  investigation_id: string;
  artifacts_fetched: number;
  evidence_extracted: number;
  findings_generated: number;
  failed_sources_count: number;
  execution_time_ms: number;
}

export interface Note {
  id: string;
  investigation_id: string;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface Tag {
  id: string;
  user_id: string;
  name: string;
}

export interface WatchlistEntry {
  id: string;
  user_id: string;
  target: string;
  module: string;
  created_at: string;
}

// ─── Pipeline interfaces ──────────────────────────────────────────────────────

/**
 * AnalyzerConfig — every Analyzer implements this instead of hardcoding
 * thresholds inline. Makes thresholds tunable and behavior self-documenting.
 */
export interface AnalyzerConfig {
  name: string;
  version: string;
  enabled: boolean;
  thresholds: Record<string, number>;
}

/**
 * Parser — transforms a raw Artifact into atomic Evidence facts.
 * No judgment applied here: that is strictly the Analyzer's job.
 */
export interface Parser<TRaw = Record<string, unknown>> {
  readonly name: string;
  readonly version: string;
  parse(raw: TRaw): ParsedEvidence[];
}

export interface ParsedEvidence {
  fact_type: string;
  fact_value: unknown;
}

/**
 * AnalyzerInput — the context an Analyzer receives.
 */
export interface AnalyzerInput {
  evidence: Evidence[];
  investigationId: string;
  target: string;
  targetType: TargetType;
}

/**
 * ProducedFinding — what an Analyzer outputs before it is persisted.
 */
export interface ProducedFinding {
  claim: string;
  severity: Severity;
  confidence_score: number;
  score_contribution: number;
  reasoning: string;
  evidence_ids: string[]; // IDs of Evidence rows that back this finding
  attack_techniques?: string[]; // MITRE ATT&CK technique IDs
}

/**
 * Analyzer — applies judgment to Evidence, produces scored Findings.
 */
export interface Analyzer {
  readonly config: AnalyzerConfig;
  analyze(input: AnalyzerInput): ProducedFinding[];
}

// ─── Extended view types (for API responses) ─────────────────────────────────

export interface InvestigationDetail extends Investigation {
  artifacts: Artifact[];
  findings: FindingWithEvidence[];
  metrics: InvestigationMetrics | null;
  notes: Note[];
  tags: Tag[];
  prior_investigations: Array<{
    id: string;
    case_number: string;
    final_score: number | null;
    created_at: string;
    status: InvestigationStatus;
  }>;
  all_evidence?: Evidence[];
}

export interface FindingWithEvidence extends Finding {
  evidence: Evidence[];
  artifact: Artifact | null; // the artifact the evidence came from
}

export interface EvidenceWithContext extends Evidence {
  artifact: Pick<Artifact, "id" | "source" | "fetched_at">;
  findings: Pick<Finding, "id" | "claim" | "severity">[];
}
