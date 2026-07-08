import { describe, it, expect } from "vitest";
import { AbuseIPDBAnalyzer } from "../AbuseIPDBAnalyzer";
import type { AnalyzerInput } from "@/lib/pipeline/types";

describe("AbuseIPDBAnalyzer", () => {
  const analyzer = new AbuseIPDBAnalyzer();
  const config = analyzer.config;

  it("returns empty array when minimum required evidence (abuse_confidence_score, total_reports) is missing/0", () => {
    const input: AnalyzerInput = {
      evidence: [],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns empty array for an IP below the abuse flag threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "abuse_confidence_score", fact_value: config.thresholds.abuseFlag - 1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "total_reports", fact_value: config.thresholds.minReports, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns MEDIUM severity for an IP exactly at the abuse flag threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "abuse_confidence_score", fact_value: config.thresholds.abuseFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "total_reports", fact_value: config.thresholds.minReports, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("MEDIUM");
    expect(findings[0].confidence_score).toBe(40);
  });

  it("returns HIGH severity for an IP exactly at the highSeverity threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "abuse_confidence_score", fact_value: config.thresholds.highSeverity, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "total_reports", fact_value: config.thresholds.minReports, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].confidence_score).toBe(78);
  });

  it("returns CRITICAL severity for an IP exactly at the criticalSeverity threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "abuse_confidence_score", fact_value: config.thresholds.criticalSeverity, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "total_reports", fact_value: config.thresholds.minReports, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].confidence_score).toBe(92);
  });

  it("caps score contribution at 20 (AbuseIPDB weight) for score 100", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "abuse_confidence_score", fact_value: 100, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "total_reports", fact_value: 50, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].score_contribution).toBeLessThanOrEqual(20);
    expect(findings[0].score_contribution).toBe(20);
  });

  it("returns a finding for Tor Exit Node regardless of abuse score", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e3", fact_type: "is_tor", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].claim).toBe("Tor Exit Node");
    expect(findings[0].severity).toBe("MEDIUM");
    expect(findings[0].evidence_ids).toEqual(["e3"]);
  });

  it("returns empty array if the IP is whitelisted, even if it has high abuse score", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "abuse_confidence_score", fact_value: 100, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "total_reports", fact_value: 50, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "is_whitelisted", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("includes correct evidence IDs", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "abuse_confidence_score", fact_value: config.thresholds.highSeverity, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "total_reports", fact_value: 10, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "isp", fact_value: "Evil ISP", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e4", fact_type: "usage_type", fact_value: "Data Center", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e5", fact_type: "unrelated", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].evidence_ids).toEqual(expect.arrayContaining(["e1", "e2", "e3", "e4"]));
    expect(findings[0].evidence_ids).not.toContain("e5");
  });
});
