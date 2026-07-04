/**
 * DomainAgeAnalyzer v1.0
 *
 * Applies judgment to WHOIS registration_date Evidence to determine if
 * a domain was recently registered — a strong phishing/malware signal.
 *
 * Uses a decay-weighted age score: the score drops off exponentially as
 * the domain ages. A domain registered 1 day ago is near maximum risk;
 * one registered 365+ days ago contributes minimal risk.
 *
 * Decay formula:
 *   ageScore = maxScore * exp(-λ * ageDays)
 *   where λ = ln(2) / halfLife
 *
 * With halfLife = 30 days:
 *   - 0 days old  → score = 15 (max, full contribution)
 *   - 7 days old  → score ≈ 11.5
 *   - 30 days old → score ≈  7.5 (half contribution)
 *   - 90 days old → score ≈  1.9
 *   - 180+ days   → score < 1 (negligible, below threshold)
 *
 * Threshold for generating a Finding: ageDays <= 30 days.
 *
 * Rationale: The Anti-Phishing Working Group (APWG) Phishing Activity
 * Trends reports consistently show that 60-70% of phishing domains are
 * used within 5 days of registration. The 30-day threshold catches the
 * tail of the acute-risk window while the decay ensures older domains
 * contribute proportionally less.
 */

import type {
  Analyzer,
  AnalyzerConfig,
  AnalyzerInput,
  ProducedFinding,
} from "@/lib/pipeline/types";

const config: AnalyzerConfig = {
  name: "DomainAgeAnalyzer",
  version: "1.0",
  enabled: true,
  thresholds: {
    recentDaysFlag: 30,      // generate a Finding if domain is <= 30 days old
    criticalDaysFlag: 3,     // CRITICAL severity if domain is <= 3 days old
    highDaysFlag: 7,         // HIGH severity if domain is <= 7 days old
    halfLifeDays: 30,        // decay half-life in days
    maxScore: 15,            // maximum score contribution (= domain_age weight in profile)
    minScore: 1,             // minimum to bother generating a Finding
  },
};

function getFactValue<T>(evidence: AnalyzerInput["evidence"], factType: string): T | null {
  const e = evidence.find((ev) => ev.fact_type === factType);
  return e ? (e.fact_value as T) : null;
}

function getEvidenceIds(evidence: AnalyzerInput["evidence"], ...factTypes: string[]): string[] {
  return evidence
    .filter((ev) => factTypes.includes(ev.fact_type))
    .map((ev) => ev.id);
}

export class DomainAgeAnalyzer implements Analyzer {
  readonly config = config;

  analyze(input: AnalyzerInput): ProducedFinding[] {
    if (!config.enabled) return [];

    const { thresholds } = config;

    const registrationDate = getFactValue<string>(input.evidence, "registration_date");
    if (!registrationDate) return [];

    const registered = new Date(registrationDate);
    if (isNaN(registered.getTime())) return [];

    const ageDays = Math.max(
      0,
      (Date.now() - registered.getTime()) / (1000 * 60 * 60 * 24)
    );

    // Only generate a Finding if within the threshold window
    if (ageDays > thresholds.recentDaysFlag) return [];

    // Decay-weighted score
    const lambda = Math.log(2) / thresholds.halfLifeDays;
    const rawScore = thresholds.maxScore * Math.exp(-lambda * ageDays);
    const scoreContribution = Math.max(
      thresholds.minScore,
      Math.round(rawScore)
    );

    let severity: ProducedFinding["severity"] = "MEDIUM";
    let confidence = 60;

    if (ageDays <= thresholds.criticalDaysFlag) {
      severity = "HIGH";
      confidence = 85;
    } else if (ageDays <= thresholds.highDaysFlag) {
      severity = "HIGH";
      confidence = 78;
    }

    const ageDaysFormatted = ageDays < 1 ? "less than 1 day" : `${Math.round(ageDays)} days`;

    return [
      {
        claim: "Recently Registered Domain",
        severity,
        confidence_score: confidence,
        score_contribution: scoreContribution,
        reasoning: `Domain registered ${ageDaysFormatted} ago (${registrationDate.slice(0, 10)}). Domains registered within 30 days are disproportionately used in phishing and malware campaigns before appearing on blocklists. Decay-weighted score: ${scoreContribution}/15.`,
        evidence_ids: getEvidenceIds(input.evidence, "registration_date"),
      },
    ];
  }
}
