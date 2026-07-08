import { describe, it, expect } from "vitest";
import { FingerprintAnalyzer } from "../FingerprintAnalyzer";
import { MITRE_MAPPINGS } from "../../attack/mitreMapping";
import type { AnalyzerInput } from "@/lib/pipeline/types";

describe("FingerprintAnalyzer", () => {
  const analyzer = new FingerprintAnalyzer();
  const config = analyzer.config;

  it("returns empty array when required evidence is missing", () => {
    const input: AnalyzerInput = {
      evidence: [],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("generates Exposed Technology Stack finding when headers or paths are present", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "server_header", fact_value: "nginx", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "x_powered_by", fact_value: "PHP", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Exposed Technology Stack");
    expect(findings[0].severity).toBe("LOW");
    expect(findings[0].confidence_score).toBe(70);
    expect(findings[0].score_contribution).toBe(config.thresholds.exposedStackScoreContrib);
    expect(findings[0].evidence_ids).toEqual(expect.arrayContaining(["e1", "e2"]));
  });

  it("returns empty array for Missing Security Headers when < 2 headers are missing", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "missing_security_headers", fact_value: ["x-frame-options"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]); // length must be >= 2 missing to generate finding
  });

  it("generates Missing Security Headers finding with LOW severity when < 2 critical headers missing", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "missing_security_headers", fact_value: ["strict-transport-security", "x-frame-options"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Missing Security Headers");
    expect(findings[0].severity).toBe("LOW");
    expect(findings[0].confidence_score).toBe(72); // 1 critical missing
  });

  it("generates Missing Security Headers finding with MEDIUM severity when >= 2 critical headers missing", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "missing_security_headers", fact_value: ["strict-transport-security", "content-security-policy", "x-frame-options"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Missing Security Headers");
    expect(findings[0].severity).toBe("MEDIUM");
    expect(findings[0].confidence_score).toBe(72);
  });

  it("generates Missing Security Headers finding with LOW severity and lower confidence when 0 critical headers missing", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "missing_security_headers", fact_value: ["x-frame-options", "referrer-policy"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Missing Security Headers");
    expect(findings[0].severity).toBe("LOW");
    expect(findings[0].confidence_score).toBe(55); // 0 critical missing
  });

  it("adds attack techniques based on mitreMapping", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "server_header", fact_value: "nginx", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "missing_security_headers", fact_value: ["strict-transport-security", "x-frame-options"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(2); // Exposed tech AND Missing headers

    const expectedTechnique = "T1592";
    expect(findings[0].attack_techniques).toContain(expectedTechnique);
    expect(findings[1].attack_techniques).toContain(expectedTechnique);
    expect(MITRE_MAPPINGS[expectedTechnique]).toBeDefined();
  });

  it("includes correct evidence IDs", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e_server", fact_type: "server_header", fact_value: "nginx", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_missing", fact_type: "missing_security_headers", fact_value: ["strict-transport-security", "x-frame-options"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_other", fact_type: "other", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    const techFinding = findings.find(f => f.claim === "Exposed Technology Stack");
    expect(techFinding?.evidence_ids).toEqual(["e_server"]);
    
    const secFinding = findings.find(f => f.claim === "Missing Security Headers");
    expect(secFinding?.evidence_ids).toEqual(["e_missing"]);
  });
});
