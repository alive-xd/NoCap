/**
 * VirusTotalAnalyzer v1.0
 *
 * Applies judgment to VirusTotal Evidence to produce scored Findings.
 * Input: Evidence extracted by VirusTotalParser.
 *
 * Produces Findings:
 *   - "Multiple Vendor Consensus" — when enough vendors flag as malicious
 *   - "Suspicious Activity Detected" — when suspicious count is significant
 *   - "Negative Reputation" — when VT community reputation is poor
 *
 * Config thresholds:
 *   flagThreshold: minimum malicious detections to generate a Finding (default: 3)
 *   highSeverityThreshold: malicious count for HIGH severity (default: 10)
 *   criticalThreshold: malicious count for CRITICAL severity (default: 25)
 *   suspiciousThreshold: suspicious count for a Finding (default: 5)
 *   reputationThreshold: VT reputation below this triggers a Finding (default: -20)
 *
 * Score contribution rationale:
 *   Capped at 40 points (the VT weight in scoring_profile v1.0).
 *   Scales linearly from flagThreshold to criticalThreshold.
 */

import type {
  Analyzer,
  AnalyzerConfig,
  AnalyzerInput,
  ProducedFinding,
} from "@/lib/pipeline/types";

const config: AnalyzerConfig = {
  name: "VirusTotalAnalyzer",
  version: "1.0",
  enabled: true,
  thresholds: {
    flagThreshold: 3,
    highSeverityThreshold: 10,
    criticalThreshold: 25,
    suspiciousThreshold: 5,
    reputationThreshold: -20,
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

export class VirusTotalAnalyzer implements Analyzer {
  readonly config = config;

  analyze(input: AnalyzerInput): ProducedFinding[] {
    if (!config.enabled) return [];

    const findings: ProducedFinding[] = [];
    const { thresholds } = config;

    const maliciousCount = getFactValue<number>(input.evidence, "malicious_count") ?? 0;
    const suspiciousCount = getFactValue<number>(input.evidence, "suspicious_count") ?? 0;
    const vendorCount = getFactValue<number>(input.evidence, "vendor_count") ?? 0;
    const reputation = getFactValue<number>(input.evidence, "reputation");
    const flaggingVendors = getFactValue<string[]>(input.evidence, "flagging_vendors") ?? [];
    const tags = getFactValue<string[]>(input.evidence, "tags") ?? [];

    // ── Finding: Multiple Vendor Consensus ────────────────────────────────────
    if (maliciousCount >= thresholds.flagThreshold) {
      let severity: ProducedFinding["severity"] = "MEDIUM";
      let confidence = 40;

      if (maliciousCount >= thresholds.criticalThreshold) {
        severity = "CRITICAL";
        confidence = 95;
      } else if (maliciousCount >= thresholds.highSeverityThreshold) {
        severity = "HIGH";
        confidence = 80;
      } else {
        // Linear scale between flagThreshold and highSeverityThreshold
        const ratio =
          (maliciousCount - thresholds.flagThreshold) /
          (thresholds.highSeverityThreshold - thresholds.flagThreshold);
        confidence = Math.round(40 + ratio * 40);
      }

      const detectionRatio =
        vendorCount > 0
          ? `${maliciousCount}/${vendorCount} vendors flagged malicious`
          : `${maliciousCount} vendors flagged malicious`;

      const topVendors = flaggingVendors.slice(0, 5).join(", ");
      const tagStr = tags.length > 0 ? ` Tags: ${tags.join(", ")}.` : "";

      // Score contribution: proportional to malicious count, capped at VT weight (40)
      const score = Math.min(
        Math.round((maliciousCount / thresholds.criticalThreshold) * 40),
        40
      );

      findings.push({
        claim: "Multiple Vendor Consensus",
        severity,
        confidence_score: confidence,
        score_contribution: score,
        reasoning: `${detectionRatio}. ${topVendors ? `Flagging vendors include: ${topVendors}.` : ""}${tagStr} Multi-vendor consensus is the strongest available signal for malicious classification.`,
        evidence_ids: getEvidenceIds(
          input.evidence,
          "malicious_count",
          "vendor_count",
          "flagging_vendors",
          "tags"
        ),
      });
    }

    // ── Finding: Suspicious Activity ─────────────────────────────────────────
    if (
      suspiciousCount >= thresholds.suspiciousThreshold &&
      maliciousCount < thresholds.flagThreshold
    ) {
      findings.push({
        claim: "Suspicious Activity Detected",
        severity: "LOW",
        confidence_score: 35,
        score_contribution: 8,
        reasoning: `${suspiciousCount} vendors flagged as suspicious. Below the malicious threshold but warrants further investigation.`,
        evidence_ids: getEvidenceIds(input.evidence, "suspicious_count", "vendor_count"),
      });
    }

    // ── Finding: Negative Community Reputation ────────────────────────────────
    if (reputation !== null && reputation < thresholds.reputationThreshold) {
      findings.push({
        claim: "Negative Community Reputation",
        severity: "LOW",
        confidence_score: 30,
        score_contribution: 5,
        reasoning: `VirusTotal community reputation score: ${reputation} (threshold: ${thresholds.reputationThreshold}). Negative community votes corroborate other malicious signals.`,
        evidence_ids: getEvidenceIds(input.evidence, "reputation"),
      });
    }

    return findings;
  }
}
