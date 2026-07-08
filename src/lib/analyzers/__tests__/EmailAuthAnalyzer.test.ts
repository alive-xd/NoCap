import { describe, it, expect } from "vitest";
import { EmailAuthAnalyzer } from "../EmailAuthAnalyzer";
import { MITRE_MAPPINGS } from "../../attack/mitreMapping";
import type { AnalyzerInput } from "@/lib/pipeline/types";

describe("EmailAuthAnalyzer", () => {
  const analyzer = new EmailAuthAnalyzer();
  const config = analyzer.config;

  it("returns empty array when required evidence is missing", () => {
    const input: AnalyzerInput = {
      evidence: [],
      investigationId: "inv",
      target: "email",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns MEDIUM severity for 1 auth failure", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "spf_result", fact_value: "fail", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "dkim_result", fact_value: "pass", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "dmarc_result", fact_value: "pass", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "email",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Email Authentication Failure");
    expect(findings[0].severity).toBe("MEDIUM");
    expect(findings[0].confidence_score).toBe(65);
    expect(findings[0].score_contribution).toBe(config.thresholds.authFailScoreContrib);
    expect(findings[0].attack_techniques).toContain("T1566");
  });

  it("returns HIGH severity for 2 auth failures", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "spf_result", fact_value: "fail", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "dkim_result", fact_value: "fail", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "dmarc_result", fact_value: "pass", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "email",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].confidence_score).toBe(80);
  });

  it("returns CRITICAL severity for 3 auth failures", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "spf_result", fact_value: "fail", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "dkim_result", fact_value: "fail", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "dmarc_result", fact_value: "fail", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "email",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].confidence_score).toBe(92);
  });

  it("generates Suspicious Email Routing finding for maxNormalHops boundary", () => {
    // Just below maxNormalHops (5)
    let input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "hop_count", fact_value: config.thresholds.maxNormalHops, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "email",
      targetType: "DOMAIN",
    };
    let findings = analyzer.analyze(input);
    expect(findings).toEqual([]);

    // Just above maxNormalHops
    input = {
      evidence: [
        { id: "e1", fact_type: "hop_count", fact_value: config.thresholds.maxNormalHops + 1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "email",
      targetType: "DOMAIN",
    };
    findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Suspicious Email Routing");
    expect(findings[0].severity).toBe("MEDIUM");
    expect(findings[0].score_contribution).toBe(config.thresholds.mismatchScoreContrib);
    expect(findings[0].attack_techniques).toContain("T1566");
  });

  it("generates Suspicious Email Routing finding for mismatches", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "mismatch_flags", fact_value: ["From domain differs from Reply-To domain"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "email",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Suspicious Email Routing");
    expect(findings[0].severity).toBe("MEDIUM");
  });

  it("adds attack techniques based on mitreMapping", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "spf_result", fact_value: "fail", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "email",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    const expectedTechnique = "T1566";
    expect(findings[0].attack_techniques).toContain(expectedTechnique);
    expect(MITRE_MAPPINGS[expectedTechnique]).toBeDefined();
  });

  it("includes correct evidence IDs", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e_spf", fact_type: "spf_result", fact_value: "fail", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_dkim", fact_type: "dkim_result", fact_value: "pass", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_mismatch", fact_type: "mismatch_flags", fact_value: ["From domain differs from Reply-To domain"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_replyto", fact_type: "reply_to_domain", fact_value: "evil.com", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_from", fact_type: "from_domain", fact_value: "bank.com", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "email",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    
    // Auth failure finding
    const authFinding = findings.find(f => f.claim === "Email Authentication Failure");
    expect(authFinding?.evidence_ids).toEqual(expect.arrayContaining(["e_spf"]));
    expect(authFinding?.evidence_ids).not.toContain("e_dkim"); // Passed
    
    // Routing finding
    const routingFinding = findings.find(f => f.claim === "Suspicious Email Routing");
    expect(routingFinding?.evidence_ids).toEqual(expect.arrayContaining(["e_mismatch", "e_replyto", "e_from"]));
  });
});
