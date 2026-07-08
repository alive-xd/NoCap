/**
 * CVEPriorityAnalyzer v1.0
 *
 * Produces a composite priority ranking for CVEs combining:
 *   1. CVSS base score (primary risk signal)
 *   2. Known public exploit availability (binary: Exploit-DB cross-reference)
 *   3. Recency-weighted publish date (exponential decay over 365 days)
 *
 * Composite formula:
 *   priority = (cvssNorm * 0.5) + (exploitBonus * 0.3) + (recencyScore * 0.2)
 *
 * where:
 *   cvssNorm      = cvssScore / 10.0  (normalizes to 0-1)
 *   exploitBonus  = 1.0 if known exploit, 0.0 otherwise
 *   recencyScore  = exp(-λ * daysSincePublish), λ = ln(2) / 180
 *
 * Rationale for weights:
 *   CVSS 50%: Standard industry risk score, widely validated. Primary factor
 *     because it captures exploitability and impact independently of popularity.
 *   Exploit availability 30%: Known public exploits dramatically increase
 *     real-world exploitation probability (CISA KEV data confirms this).
 *     Binary factor because the existence of any exploit matters more than how
 *     many — the first exploit does most of the risk work.
 *   Recency 20%: Attackers prioritize newly disclosed CVEs before defenders
 *     can patch. Exponential decay with 180-day half-life; after ~1 year,
 *     recency contributes negligibly. Newer CVEs get a meaningful boost.
 *
 * Sources:
 *   - CVSS: NIST NVD (fetched via NVD API 2.0)
 *   - Exploit availability: Exploit-DB free CSV
 *     (https://www.exploit-db.com/files_exploits.csv)
 *     Downloaded and parsed at runtime — no API key required.
 *   - CISA KEV (Known Exploited Vulnerabilities):
 *     https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 *     Checked as a secondary exploit-availability signal.
 */

import type {
  Analyzer,
  AnalyzerConfig,
  AnalyzerInput,
  ProducedFinding,
} from "@/lib/pipeline/types";

const config: AnalyzerConfig = {
  name: "CVEPriorityAnalyzer",
  version: "1.0",
  enabled: true,
  thresholds: {
    criticalCVSS: 9.0,       // CVSS >= 9.0 = CRITICAL severity
    highCVSS: 7.0,            // CVSS >= 7.0 = HIGH severity
    mediumCVSS: 4.0,          // CVSS >= 4.0 = MEDIUM severity
    recencyHalfLifeDays: 180, // decay half-life for publish date score
    cvssWeight: 0.5,
    exploitWeight: 0.3,
    recencyWeight: 0.2,
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

export class CVEPriorityAnalyzer implements Analyzer {
  readonly config = config;

  analyze(input: AnalyzerInput): ProducedFinding[] {
    if (!config.enabled) return [];

    const { thresholds } = config;

    const cveId = getFactValue<string>(input.evidence, "cve_id");
    const cvssScore = getFactValue<number>(input.evidence, "cvss_score");
    const publishDate = getFactValue<string>(input.evidence, "publish_date");
    const hasKnownExploit = getFactValue<boolean>(input.evidence, "has_known_exploit") ?? false;
    const inCisaKev = getFactValue<boolean>(input.evidence, "in_cisa_kev") ?? false;
    const description = getFactValue<string>(input.evidence, "description") ?? "";

    if (!cveId || cvssScore === null || !publishDate) return [];

    // ── Composite priority score ───────────────────────────────────────────────
    const cvssNorm = cvssScore / 10.0;

    const exploitBonus = hasKnownExploit || inCisaKev ? 1.0 : 0.0;

    const daysSincePublish = Math.max(
      0,
      (Date.now() - new Date(publishDate).getTime()) / (1000 * 60 * 60 * 24)
    );
    const lambda = Math.log(2) / thresholds.recencyHalfLifeDays;
    const recencyScore = Math.exp(-lambda * daysSincePublish);

    const priorityRaw =
      cvssNorm * thresholds.cvssWeight +
      exploitBonus * thresholds.exploitWeight +
      recencyScore * thresholds.recencyWeight;

    const priorityScore = Math.round(priorityRaw * 100);
    const confidence = Math.min(50 + Math.round(priorityRaw * 50), 98);

    // ── Severity from CVSS ────────────────────────────────────────────────────
    let severity: ProducedFinding["severity"] = "LOW";
    if (cvssScore >= thresholds.criticalCVSS) severity = "CRITICAL";
    else if (cvssScore >= thresholds.highCVSS) severity = "HIGH";
    else if (cvssScore >= thresholds.mediumCVSS) severity = "MEDIUM";

    const exploitStr = inCisaKev
      ? "In CISA KEV (actively exploited in the wild)"
      : hasKnownExploit
      ? "Known public exploit available (Exploit-DB)"
      : "No known public exploit";

    return [
      {
        claim: `CVE Priority: ${cveId}`,
        severity,
        confidence_score: confidence,
        score_contribution: Math.min(priorityScore, 20),
        reasoning: `CVSS: ${cvssScore}/10. ${exploitStr}. Published ${Math.round(daysSincePublish)} days ago. Composite priority score: ${priorityScore}/100 (CVSS 50% + exploit 30% + recency 20%). ${description.slice(0, 200)}${description.length > 200 ? "…" : ""}`,
        attack_techniques: ['T1588.006'],
        evidence_ids: getEvidenceIds(
          input.evidence,
          "cve_id",
          "cvss_score",
          "publish_date",
          "has_known_exploit",
          "in_cisa_kev",
          "description"
        ),
      },
    ];
  }
}
