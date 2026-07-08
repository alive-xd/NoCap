import { describe, it, expect } from "vitest";
import { VirusTotalAnalyzer } from "../VirusTotalAnalyzer";
import type { AnalyzerInput } from "@/lib/pipeline/types";

describe("VirusTotalAnalyzer", () => {
  const analyzer = new VirusTotalAnalyzer();
  const config = analyzer.config;

  it("returns empty array when minimum required evidence is missing or below threshold", () => {
    const input: AnalyzerInput = {
      evidence: [],
      investigationId: "inv",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns MEDIUM severity for malicious count exactly at flagThreshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "malicious_count", fact_value: config.thresholds.flagThreshold, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Multiple Vendor Consensus");
    expect(findings[0].severity).toBe("MEDIUM");
    expect(findings[0].confidence_score).toBe(40);
  });

  it("returns HIGH severity for malicious count exactly at highSeverityThreshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "malicious_count", fact_value: config.thresholds.highSeverityThreshold, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].confidence_score).toBe(80);
  });

  it("returns CRITICAL severity for malicious count exactly at criticalThreshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "malicious_count", fact_value: config.thresholds.criticalThreshold, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].confidence_score).toBe(95);
  });

  it("caps score contribution at 40", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "malicious_count", fact_value: 100, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].score_contribution).toBeLessThanOrEqual(40);
    expect(findings[0].score_contribution).toBe(40);
  });

  it("generates Suspicious Activity Detected finding when suspicious is at threshold and malicious is below flag", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "suspicious_count", fact_value: config.thresholds.suspiciousThreshold, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "malicious_count", fact_value: config.thresholds.flagThreshold - 1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Suspicious Activity Detected");
    expect(findings[0].severity).toBe("LOW");
  });

  it("generates Negative Community Reputation finding when reputation is below threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "reputation", fact_value: config.thresholds.reputationThreshold - 1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Negative Community Reputation");
    expect(findings[0].severity).toBe("LOW");
  });

  it("includes correct evidence IDs", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e_mal", fact_type: "malicious_count", fact_value: config.thresholds.highSeverityThreshold, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_vendor", fact_type: "vendor_count", fact_value: 90, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_flagging", fact_type: "flagging_vendors", fact_value: ["VendorA"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_tags", fact_type: "tags", fact_value: ["malware"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_rep", fact_type: "reputation", fact_value: config.thresholds.reputationThreshold - 10, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_other", fact_type: "other", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    
    const consensusFinding = findings.find(f => f.claim === "Multiple Vendor Consensus");
    expect(consensusFinding?.evidence_ids).toEqual(expect.arrayContaining(["e_mal", "e_vendor", "e_flagging", "e_tags"]));
    expect(consensusFinding?.evidence_ids).not.toContain("e_rep");
    
    const repFinding = findings.find(f => f.claim === "Negative Community Reputation");
    expect(repFinding?.evidence_ids).toEqual(["e_rep"]);
  });
});
