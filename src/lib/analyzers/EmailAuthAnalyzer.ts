/**
 * EmailAuthAnalyzer v1.0
 *
 * Applies judgment to EmailHeaderParser Evidence to detect authentication
 * failures and suspicious routing patterns.
 *
 * Email authentication failures are a primary phishing indicator:
 *   - SPF fail/softfail: sending server not authorized by the domain's SPF record
 *   - DKIM fail: message signature invalid — message may have been tampered with
 *   - DMARC fail: neither SPF nor DKIM alignment — domain policy violated
 *   - Reply-To mismatch: common in business email compromise (BEC) attacks
 *   - Excessive hops: unusual for legitimate mail; may indicate relay-chain obfuscation
 *
 * Produces Findings:
 *   - "Email Authentication Failure" — SPF/DKIM/DMARC failures
 *   - "Suspicious Email Routing" — domain mismatches, excessive hops
 */

import type {
  Analyzer,
  AnalyzerConfig,
  AnalyzerInput,
  ProducedFinding,
} from "@/lib/pipeline/types";

const config: AnalyzerConfig = {
  name: "EmailAuthAnalyzer",
  version: "1.0",
  enabled: true,
  thresholds: {
    maxNormalHops: 5,         // more than 5 hops is unusual
    mismatchScoreContrib: 12, // score for domain mismatch finding
    authFailScoreContrib: 15, // score for auth failure finding
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

export class EmailAuthAnalyzer implements Analyzer {
  readonly config = config;

  analyze(input: AnalyzerInput): ProducedFinding[] {
    if (!config.enabled) return [];

    const findings: ProducedFinding[] = [];
    const { thresholds } = config;

    const spfResult = getFactValue<string>(input.evidence, "spf_result");
    const dkimResult = getFactValue<string>(input.evidence, "dkim_result");
    const dmarcResult = getFactValue<string>(input.evidence, "dmarc_result");
    const mismatches = getFactValue<string[]>(input.evidence, "mismatch_flags") ?? [];
    const hopCount = getFactValue<number>(input.evidence, "hop_count") ?? 0;

    // ── Finding: Email Authentication Failure ─────────────────────────────────
    const authFailures: string[] = [];
    const failedResults: string[] = [];

    if (spfResult && ["fail", "softfail", "permerror"].includes(spfResult)) {
      authFailures.push(`SPF ${spfResult}`);
      failedResults.push("spf_result");
    }
    if (dkimResult === "fail") {
      authFailures.push("DKIM signature failed");
      failedResults.push("dkim_result");
    }
    if (dmarcResult === "fail") {
      authFailures.push("DMARC policy violated");
      failedResults.push("dmarc_result");
    }

    if (authFailures.length > 0) {
      // All three failing = CRITICAL, two = HIGH, one = MEDIUM
      let severity: ProducedFinding["severity"] = "MEDIUM";
      let confidence = 65;

      if (authFailures.length >= 3) {
        severity = "CRITICAL";
        confidence = 92;
      } else if (authFailures.length >= 2) {
        severity = "HIGH";
        confidence = 80;
      }

      findings.push({
        claim: "Email Authentication Failure",
        severity,
        confidence_score: confidence,
        score_contribution: thresholds.authFailScoreContrib,
        reasoning: `${authFailures.join("; ")}. Failure of email authentication protocols (SPF/DKIM/DMARC) indicates the sender is not authorized to send on behalf of the claimed domain, or the message was modified in transit. Combined failures are a strong phishing indicator.`,
        evidence_ids: getEvidenceIds(input.evidence, ...failedResults, "mismatch_flags"),
      });
    }

    // ── Finding: Suspicious Email Routing ─────────────────────────────────────
    const routingIssues: string[] = [];
    const routingEvidenceTypes: string[] = [];

    for (const mismatch of mismatches) {
      if (mismatch.includes("Reply-To") || mismatch.includes("Return-Path")) {
        routingIssues.push(mismatch);
        routingEvidenceTypes.push("mismatch_flags", "reply_to_domain", "from_domain");
      }
    }

    if (hopCount > thresholds.maxNormalHops) {
      routingIssues.push(
        `Unusual hop count: ${hopCount} (normal maximum: ${thresholds.maxNormalHops})`
      );
      routingEvidenceTypes.push("hop_count", "received_hops");
    }

    if (routingIssues.length > 0) {
      findings.push({
        claim: "Suspicious Email Routing",
        severity: "MEDIUM",
        confidence_score: 60,
        score_contribution: thresholds.mismatchScoreContrib,
        reasoning: `${routingIssues.join("; ")}. Reply-To/From mismatches are a primary Business Email Compromise (BEC) indicator. Excessive relay hops can indicate deliberate obfuscation of the true sending origin.`,
        evidence_ids: getEvidenceIds(
          input.evidence,
          ...new Set(routingEvidenceTypes)
        ),
      });
    }

    return findings;
  }
}
