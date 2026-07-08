/**
 * FingerprintAnalyzer v1.0
 *
 * Identifies technology stack and security posture from HTTP response
 * headers and specific path probes collected during Attack Surface investigation.
 *
 * Signature set design:
 *   Technology signatures are grouped into categories:
 *     - Response headers (Server, X-Powered-By, X-Generator, X-AspNet-Version)
 *     - Cookie names (PHPSESSID = PHP, JSESSIONID = Java/Tomcat, ASP.NET_SessionId)
 *     - Framework-specific path probes (/.well-known/security.txt, /wp-login.php, etc.)
 *     - Security header presence/absence (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
 *
 * Produces Findings:
 *   - "Exposed Technology Stack" — when server software or framework is identifiable
 *   - "Missing Security Headers" — when critical security headers are absent
 *
 * The security header check is based on:
 *   OWASP Secure Headers Project (https://owasp.org/www-project-secure-headers/)
 *   Mozilla Observatory header recommendations
 *
 * Note: FingerprintAnalyzer receives its Evidence from the orchestrator,
 * which probes the domain's HTTP endpoints and stores results as an Artifact.
 * The analyzer itself does no network I/O — only Evidence processing.
 */

import type {
  Analyzer,
  AnalyzerConfig,
  AnalyzerInput,
  ProducedFinding,
} from "@/lib/pipeline/types";

const config: AnalyzerConfig = {
  name: "FingerprintAnalyzer",
  version: "1.0",
  enabled: true,
  thresholds: {
    missingHeaderScoreContrib: 8,
    exposedStackScoreContrib: 5,
  },
};

// Critical security headers — absence is a finding
const REQUIRED_SECURITY_HEADERS = [
  { header: "strict-transport-security", label: "HSTS", critical: true },
  { header: "content-security-policy", label: "Content-Security-Policy", critical: true },
  { header: "x-frame-options", label: "X-Frame-Options", critical: false },
  { header: "x-content-type-options", label: "X-Content-Type-Options", critical: false },
  { header: "referrer-policy", label: "Referrer-Policy", critical: false },
];

function getFactValue<T>(evidence: AnalyzerInput["evidence"], factType: string): T | null {
  const e = evidence.find((ev) => ev.fact_type === factType);
  return e ? (e.fact_value as T) : null;
}

function getEvidenceIds(evidence: AnalyzerInput["evidence"], ...factTypes: string[]): string[] {
  return evidence
    .filter((ev) => factTypes.includes(ev.fact_type))
    .map((ev) => ev.id);
}

export class FingerprintAnalyzer implements Analyzer {
  readonly config = config;

  analyze(input: AnalyzerInput): ProducedFinding[] {
    if (!config.enabled) return [];

    const findings: ProducedFinding[] = [];
    const { thresholds } = config;

    // Evidence fact types produced by the HTTP fingerprinting artifact
    const serverHeader = getFactValue<string>(input.evidence, "server_header");
    const poweredBy = getFactValue<string>(input.evidence, "x_powered_by");
    const generator = getFactValue<string>(input.evidence, "x_generator");
    const aspNetVersion = getFactValue<string>(input.evidence, "x_aspnet_version");
    const detectedTech = getFactValue<string[]>(input.evidence, "detected_tech") ?? [];
    const presentHeaders = getFactValue<string[]>(input.evidence, "present_security_headers") ?? [];
    const missingHeaders = getFactValue<string[]>(input.evidence, "missing_security_headers") ?? [];
    const exposedPaths = getFactValue<string[]>(input.evidence, "exposed_paths") ?? [];

    // ── Finding: Exposed Technology Stack ─────────────────────────────────────
    const identifiers: string[] = [];
    if (serverHeader) identifiers.push(`Server: ${serverHeader}`);
    if (poweredBy) identifiers.push(`X-Powered-By: ${poweredBy}`);
    if (generator) identifiers.push(`X-Generator: ${generator}`);
    if (aspNetVersion) identifiers.push(`X-AspNet-Version: ${aspNetVersion}`);
    if (detectedTech.length > 0) identifiers.push(...detectedTech);
    if (exposedPaths.length > 0) identifiers.push(`Exposed paths: ${exposedPaths.join(", ")}`);

    if (identifiers.length > 0) {
      findings.push({
        claim: "Exposed Technology Stack",
        severity: "LOW",
        confidence_score: 70,
        score_contribution: thresholds.exposedStackScoreContrib,
        reasoning: `Server technology identifiable from response headers and path probes: ${identifiers.join("; ")}. Exposing server software and framework versions aids targeted exploitation by providing attackers with a precise attack surface.`,
        attack_techniques: ['T1592'],
        evidence_ids: getEvidenceIds(
          input.evidence,
          "server_header",
          "x_powered_by",
          "x_generator",
          "x_aspnet_version",
          "detected_tech",
          "exposed_paths"
        ),
      });
    }

    // ── Finding: Missing Security Headers ─────────────────────────────────────
    const criticalMissing = missingHeaders.filter((h) =>
      REQUIRED_SECURITY_HEADERS.find(
        (r) => r.header === h.toLowerCase() && r.critical
      )
    );
    const nonCriticalMissing = missingHeaders.filter(
      (h) => !criticalMissing.includes(h)
    );
    const allMissing = [...criticalMissing, ...nonCriticalMissing];

    if (allMissing.length >= 2) {
      const severity: ProducedFinding["severity"] =
        criticalMissing.length >= 2 ? "MEDIUM" : "LOW";
      const confidence = criticalMissing.length >= 1 ? 72 : 55;

      findings.push({
        claim: "Missing Security Headers",
        severity,
        confidence_score: confidence,
        score_contribution: thresholds.missingHeaderScoreContrib,
        reasoning: `Missing security headers: ${allMissing.join(", ")}. Critical missing: ${criticalMissing.length > 0 ? criticalMissing.join(", ") : "none"}. Present: ${presentHeaders.length > 0 ? presentHeaders.join(", ") : "none"}. Based on OWASP Secure Headers Project and Mozilla Observatory recommendations.`,
        attack_techniques: ['T1592'],
        evidence_ids: getEvidenceIds(
          input.evidence,
          "missing_security_headers",
          "present_security_headers"
        ),
      });
    }

    return findings;
  }
}
