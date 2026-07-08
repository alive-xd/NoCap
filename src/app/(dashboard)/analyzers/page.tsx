// Analyzer Library — static metadata for every Analyzer in the system
// This is the in-app documentation page.

import { MITRE_MAPPINGS } from "@/lib/attack/mitreMapping";

const ANALYZER_LIBRARY = [
  {
    name: "VirusTotalAnalyzer",
    version: "1.0",
    badge: "VT",
    purpose: "Applies judgment to VirusTotal multi-engine scan results to determine malicious consensus.",
    thresholds: {
      flagThreshold: 3,
      highSeverityThreshold: 10,
      criticalThreshold: 25,
      suspiciousThreshold: 5,
      reputationThreshold: -20,
    },
    requiredEvidence: ["malicious_count", "suspicious_count", "vendor_count", "flagging_vendors", "reputation", "tags"],
    producesFindings: [
      "Multiple Vendor Consensus",
      "Suspicious Activity Detected",
      "Negative Community Reputation",
    ],
    exampleFinding: {
      claim: "Multiple Vendor Consensus",
      severity: "HIGH",
      confidence: 80,
      scoreContribution: 25,
      reasoning: "18/70 vendors flagged malicious. Flagging vendors include: Microsoft, Kaspersky, Sophos, ESET, Avast.",
    },
  },
  {
    name: "AbuseIPDBAnalyzer",
    version: "1.0",
    badge: "ABUSE",
    purpose: "Determines IP abuse status from community-reported abuse confidence score and report count.",
    thresholds: {
      abuseFlag: 25,
      highSeverity: 75,
      criticalSeverity: 90,
      minReports: 2,
    },
    requiredEvidence: ["abuse_confidence_score", "total_reports", "is_whitelisted", "is_tor", "isp", "usage_type"],
    producesFindings: ["Known Abusive IP Address", "Tor Exit Node"],
    exampleFinding: {
      claim: "Known Abusive IP Address",
      severity: "HIGH",
      confidence: 78,
      scoreContribution: 18,
      reasoning: "AbuseIPDB confidence score: 87% based on 143 community reports. ISP: AS9009 M247 Ltd.",
    },
  },
  {
    name: "DomainAgeAnalyzer",
    version: "1.0",
    badge: "WHOIS",
    purpose: "Detects recently registered domains using decay-weighted age scoring. Newly registered domains are disproportionately used in phishing campaigns.",
    thresholds: {
      recentDaysFlag: 30,
      criticalDaysFlag: 3,
      highDaysFlag: 7,
      halfLifeDays: 30,
      maxScore: 15,
      minScore: 1,
    },
    requiredEvidence: ["registration_date"],
    producesFindings: ["Recently Registered Domain"],
    attackTechniques: ['T1583.001'],
    exampleFinding: {
      claim: "Recently Registered Domain",
      severity: "HIGH",
      confidence: 85,
      scoreContribution: 15,
      reasoning: "Domain registered 3 days ago (2026-07-01). Decay-weighted score: 15/15. Source: APWG Q1 2024.",
    },
  },
  {
    name: "EntropyAnalyzer",
    version: "1.0",
    badge: "ENT",
    purpose: "Detects algorithmically generated domains (DGA) by computing Shannon entropy of the second-level domain label.",
    thresholds: {
      entropyFlag: 3.9,
      highEntropyFlag: 4.2,
      highDigitRatioFlag: 0.15,
      minSldLength: 5,
    },
    requiredEvidence: ["entropy_score", "domain_string", "sld", "digit_ratio", "consonant_ratio", "sld_length"],
    producesFindings: ["High Entropy Domain"],
    attackTechniques: ['T1568.002'],
    exampleFinding: {
      claim: "High Entropy Domain",
      severity: "HIGH",
      confidence: 82,
      scoreContribution: 12,
      reasoning: 'Domain string: "ajkx83qk.info" (SLD: "ajkx83qk"). Entropy: 4.81 (threshold: 3.9). Digit ratio: 25%. Threshold from Antonakakis et al. (USENIX Security 2012).',
    },
  },
  {
    name: "ASNReputationAnalyzer",
    version: "1.0",
    badge: "ASN",
    purpose: "Cross-references the IP's ASN against a curated list of known-abusive autonomous systems compiled from Spamhaus, Feodo Tracker, abuse.ch, and GreyNoise.",
    thresholds: {
      tier1ScoreContribution: 12,
      tier2ScoreContribution: 6,
    },
    requiredEvidence: ["asn_number", "asn", "org", "isp"],
    producesFindings: ["Known Abusive ASN"],
    attackTechniques: ['T1583.003', 'T1583.004'],
    exampleFinding: {
      claim: "Known Abusive ASN",
      severity: "HIGH",
      confidence: 75,
      scoreContribution: 12,
      reasoning: "AS9009 (M247 Ltd) is on the NoCap abuse ASN list (Tier 1). Reason: Frequent bulletproof hosting provider for malware C2 and spam. Sources: Spamhaus ASN-DROP, Feodo Tracker.",
    },
  },
  {
    name: "HomographAnalyzer",
    version: "1.0",
    badge: "HOM",
    purpose: "Detects brand impersonation through visual character substitution (homograph attacks) using Levenshtein distance comparison against a 50-brand list.",
    thresholds: {
      distanceFlag: 2,
      extendedDistanceFlag: 3,
    },
    requiredEvidence: ["closest_distance", "closest_brand", "input_domain", "input_sld", "all_candidates"],
    producesFindings: ["Potential Brand Impersonation"],
    attackTechniques: ['T1566'],
    exampleFinding: {
      claim: "Potential Brand Impersonation",
      severity: "HIGH",
      confidence: 80,
      scoreContribution: 20,
      reasoning: 'Domain "paypa1.com" (SLD: "paypa1") has Levenshtein distance 1 from brand "paypal". Homograph normalization (1→l) applied.',
    },
  },
  {
    name: "EmailAuthAnalyzer",
    version: "1.0",
    badge: "HDR",
    purpose: "Evaluates email authentication results (SPF/DKIM/DMARC) and routing anomalies to detect phishing and Business Email Compromise (BEC).",
    thresholds: {
      maxNormalHops: 5,
      mismatchScoreContrib: 12,
      authFailScoreContrib: 15,
    },
    requiredEvidence: ["spf_result", "dkim_result", "dmarc_result", "mismatch_flags", "hop_count", "received_hops"],
    producesFindings: ["Email Authentication Failure", "Suspicious Email Routing"],
    attackTechniques: ['T1566'],
    exampleFinding: {
      claim: "Email Authentication Failure",
      severity: "CRITICAL",
      confidence: 92,
      scoreContribution: 15,
      reasoning: "SPF fail; DKIM signature failed; DMARC policy violated. All three authentication protocols failed — strong phishing indicator.",
    },
  },
  {
    name: "FingerprintAnalyzer",
    version: "1.0",
    badge: "FP",
    purpose: "Identifies exposed technology stack from HTTP response headers and detects missing OWASP-recommended security headers.",
    thresholds: {
      missingHeaderScoreContrib: 8,
      exposedStackScoreContrib: 5,
    },
    requiredEvidence: ["server_header", "x_powered_by", "x_generator", "detected_tech", "missing_security_headers", "present_security_headers", "exposed_paths"],
    producesFindings: ["Exposed Technology Stack", "Missing Security Headers"],
    attackTechniques: ['T1592'],
    exampleFinding: {
      claim: "Missing Security Headers",
      severity: "MEDIUM",
      confidence: 72,
      scoreContribution: 8,
      reasoning: "Missing: strict-transport-security, content-security-policy. Present: x-frame-options. Based on OWASP Secure Headers Project.",
    },
  },
  {
    name: "CVEPriorityAnalyzer",
    version: "1.0",
    badge: "CVE",
    purpose: "Computes composite CVE priority score combining CVSS base score (50%), known exploit availability (30%), and recency-weighted publish date (20%).",
    thresholds: {
      criticalCVSS: 9.0,
      highCVSS: 7.0,
      mediumCVSS: 4.0,
      recencyHalfLifeDays: 180,
      cvssWeight: 0.5,
      exploitWeight: 0.3,
      recencyWeight: 0.2,
    },
    requiredEvidence: ["cve_id", "cvss_score", "publish_date", "has_known_exploit", "in_cisa_kev", "description"],
    producesFindings: ["CVE Priority: [CVE-ID]"],
    exampleFinding: {
      claim: "CVE Priority: CVE-2024-21413",
      severity: "CRITICAL",
      confidence: 94,
      scoreContribution: 18,
      reasoning: "CVSS: 9.8/10. In CISA KEV (actively exploited in the wild). Published 8 days ago. Composite priority: 87/100.",
    },
  },
];

export default function AnalyzerLibraryPage() {
  return (
    <>
      <style>{`
        .library-page { padding: 2rem 2.5rem; max-width: 1000px; }

        .library-header {
          margin-bottom: 2rem;
          padding-bottom: 1.5rem;
          border-bottom: var(--border);
        }

        .library-title {
          font-family: var(--font-display);
          font-size: 1.5rem;
          font-weight: 500;
          color: var(--text-primary);
          margin-bottom: 0.25rem;
        }

        .library-subtitle {
          font-size: 0.875rem;
          color: var(--text-secondary);
        }

        .analyzer-card {
          background: var(--bg-surface);
          border: var(--border);
          border-radius: var(--radius-md);
          margin-bottom: 1.25rem;
          overflow: hidden;
        }

        .analyzer-card-header {
          padding: 1rem 1.25rem;
          border-bottom: var(--border);
          display: flex;
          align-items: center;
          gap: 1rem;
        }

        .analyzer-name {
          font-family: var(--font-display);
          font-size: 1.0625rem;
          font-weight: 500;
          color: var(--text-primary);
          flex: 1;
        }

        .analyzer-version {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--text-tertiary);
          border: 1px solid var(--bg-border);
          padding: 2px 8px;
          border-radius: 2px;
        }

        .analyzer-card-body {
          padding: 1.25rem;
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1.25rem;
        }

        .analyzer-section-label {
          font-family: var(--font-mono);
          font-size: 0.625rem;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          color: var(--text-tertiary);
          margin-bottom: 0.5rem;
        }

        .analyzer-purpose {
          font-size: 0.875rem;
          color: var(--text-secondary);
          line-height: 1.6;
          grid-column: 1 / -1;
        }

        .threshold-list {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .threshold-row {
          display: flex;
          justify-content: space-between;
          padding: 4px 8px;
          border-radius: var(--radius-sm);
          background: var(--bg-surface-2);
        }

        .threshold-key {
          font-family: var(--font-mono);
          font-size: 0.75rem;
          color: var(--text-secondary);
        }

        .threshold-val {
          font-family: var(--font-mono);
          font-size: 0.75rem;
          color: var(--accent-open);
        }

        .evidence-pills {
          display: flex;
          flex-wrap: wrap;
          gap: 4px;
        }

        .evidence-pill {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          padding: 2px 8px;
          border: 1px solid var(--bg-border);
          border-radius: 2px;
          color: var(--text-tertiary);
        }

        .example-finding-box {
          grid-column: 1 / -1;
          background: var(--bg-base);
          border: var(--border);
          border-left: 3px solid var(--accent-confirmed);
          border-radius: var(--radius-sm);
          padding: 12px 14px;
        }

        .example-finding-claim {
          font-weight: 500;
          color: var(--text-primary);
          margin-bottom: 4px;
        }

        .example-finding-meta {
          display: flex;
          gap: 10px;
          margin-bottom: 6px;
          flex-wrap: wrap;
        }

        .example-finding-reasoning {
          font-size: 0.8125rem;
          color: var(--text-secondary);
          line-height: 1.5;
        }

        .findings-produces {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .finding-name-pill {
          font-size: 0.8125rem;
          color: var(--text-secondary);
          padding: 3px 10px;
          border: 1px solid var(--bg-border);
          border-radius: 2px;
          background: var(--bg-surface-2);
        }
      `}</style>

      <div className="library-page">
        <div className="library-header">
          <h1 className="library-title">Analyzer Library</h1>
          <p className="library-subtitle">
            Every Analyzer in the NoCap pipeline — name, version, thresholds, required Evidence inputs, and example Findings produced.
          </p>
        </div>

        {ANALYZER_LIBRARY.map((analyzer) => (
          <div key={analyzer.name} className="analyzer-card" id={`analyzer-${analyzer.name}`}>
            <div className="analyzer-card-header">
              <span
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.6875rem",
                  fontWeight: 600,
                  padding: "4px 8px",
                  background: "var(--bg-surface-2)",
                  border: "1px solid var(--bg-border)",
                  borderRadius: "2px",
                  color: "var(--accent-open)",
                  letterSpacing: "0.08em",
                }}
              >
                {analyzer.badge}
              </span>
              <span className="analyzer-name">{analyzer.name}</span>
              <span className="analyzer-version">v{analyzer.version}</span>
            </div>

            <div className="analyzer-card-body">
              <p className="analyzer-purpose">{analyzer.purpose}</p>

              <div>
                <div className="analyzer-section-label">Thresholds</div>
                <div className="threshold-list">
                  {Object.entries(analyzer.thresholds).map(([k, v]) => (
                    <div key={k} className="threshold-row">
                      <span className="threshold-key">{k}</span>
                      <span className="threshold-val">{v}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <div className="analyzer-section-label">Required Evidence Inputs</div>
                <div className="evidence-pills">
                  {analyzer.requiredEvidence.map((ev) => (
                    <span key={ev} className="evidence-pill">{ev}</span>
                  ))}
                </div>

                {analyzer.attackTechniques && analyzer.attackTechniques.length > 0 && (
                  <>
                    <div className="analyzer-section-label" style={{ marginTop: "1rem" }}>ATT&CK Techniques</div>
                    <div className="evidence-pills" style={{ marginBottom: "1rem" }}>
                      {analyzer.attackTechniques.map((tId: string) => {
                        const t = MITRE_MAPPINGS[tId];
                        return (
                          <span key={tId} className="evidence-pill" title={t?.tactic}>
                            {tId}: {t?.techniqueName}
                          </span>
                        );
                      })}
                    </div>
                  </>
                )}
                <div className="analyzer-section-label" style={{ marginTop: "1rem" }}>Produces Findings</div>
                <div className="findings-produces">
                  {analyzer.producesFindings.map((f) => (
                    <span key={f} className="finding-name-pill">{f}</span>
                  ))}
                </div>
              </div>

              <div className="example-finding-box">
                <div className="analyzer-section-label">Example Finding</div>
                <div className="example-finding-claim">{analyzer.exampleFinding.claim}</div>
                <div className="example-finding-meta">
                  <span className={`severity-badge severity-${analyzer.exampleFinding.severity}`}>
                    {analyzer.exampleFinding.severity}
                  </span>
                  <span className="mono" style={{ fontSize: "0.75rem", color: "var(--text-tertiary)" }}>
                    Confidence: {analyzer.exampleFinding.confidence}
                  </span>
                  <span className="mono" style={{ fontSize: "0.75rem", color: "var(--accent-open)" }}>
                    +{analyzer.exampleFinding.scoreContribution} pts
                  </span>
                </div>
                <p className="example-finding-reasoning">{analyzer.exampleFinding.reasoning}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
