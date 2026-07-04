/**
 * AbuseIPDBAnalyzer v1.0
 *
 * Applies judgment to AbuseIPDB Evidence to produce scored Findings.
 * Input: Evidence extracted by AbuseIPDBParser.
 *
 * Thresholds:
 *   abuseFlag: 25     — minimum abuse confidence to generate a Finding
 *   highSeverity: 75  — confidence score for HIGH severity
 *   torBonus: true    — Tor exit node adds additional severity
 *
 * Score contribution: capped at the AbuseIPDB weight in scoring_profile v1.0 (20).
 */

import type {
  Analyzer,
  AnalyzerConfig,
  AnalyzerInput,
  ProducedFinding,
} from "@/lib/pipeline/types";

const config: AnalyzerConfig = {
  name: "AbuseIPDBAnalyzer",
  version: "1.0",
  enabled: true,
  thresholds: {
    abuseFlag: 25,
    highSeverity: 75,
    criticalSeverity: 90,
    minReports: 2,     // require at least 2 reports to reduce false positives
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

export class AbuseIPDBAnalyzer implements Analyzer {
  readonly config = config;

  analyze(input: AnalyzerInput): ProducedFinding[] {
    if (!config.enabled) return [];

    const findings: ProducedFinding[] = [];
    const { thresholds } = config;

    const abuseScore = getFactValue<number>(input.evidence, "abuse_confidence_score") ?? 0;
    const totalReports = getFactValue<number>(input.evidence, "total_reports") ?? 0;
    const isTor = getFactValue<boolean>(input.evidence, "is_tor") ?? false;
    const isWhitelisted = getFactValue<boolean>(input.evidence, "is_whitelisted") ?? false;
    const usageType = getFactValue<string>(input.evidence, "usage_type") ?? "";
    const isp = getFactValue<string>(input.evidence, "isp") ?? "";

    // Whitelisted IPs generate no findings
    if (isWhitelisted) return findings;

    // ── Finding: Known Abusive IP ─────────────────────────────────────────────
    if (
      abuseScore >= thresholds.abuseFlag &&
      totalReports >= thresholds.minReports
    ) {
      let severity: ProducedFinding["severity"] = "MEDIUM";
      let confidence = 40;

      if (abuseScore >= thresholds.criticalSeverity) {
        severity = "CRITICAL";
        confidence = 92;
      } else if (abuseScore >= thresholds.highSeverity) {
        severity = "HIGH";
        confidence = 78;
      } else {
        const ratio =
          (abuseScore - thresholds.abuseFlag) /
          (thresholds.highSeverity - thresholds.abuseFlag);
        confidence = Math.round(40 + ratio * 38);
      }

      const score = Math.min(
        Math.round((abuseScore / 100) * 20),
        20
      );

      findings.push({
        claim: "Known Abusive IP Address",
        severity,
        confidence_score: confidence,
        score_contribution: score,
        reasoning: `AbuseIPDB confidence score: ${abuseScore}% based on ${totalReports} community reports.${isp ? ` ISP: ${isp}.` : ""}${usageType ? ` Usage type: ${usageType}.` : ""} Community-sourced abuse confidence is a strong corroborating signal.`,
        evidence_ids: getEvidenceIds(
          input.evidence,
          "abuse_confidence_score",
          "total_reports",
          "is_whitelisted",
          "isp",
          "usage_type"
        ),
      });
    }

    // ── Finding: Tor Exit Node ────────────────────────────────────────────────
    if (isTor) {
      findings.push({
        claim: "Tor Exit Node",
        severity: "MEDIUM",
        confidence_score: 90,
        score_contribution: 8,
        reasoning: `This IP is identified as a Tor network exit node. Traffic from Tor exit nodes is frequently used to anonymize malicious activity, though legitimate privacy use also exists. Treat as a contextual risk factor.`,
        evidence_ids: getEvidenceIds(input.evidence, "is_tor"),
      });
    }

    return findings;
  }
}
