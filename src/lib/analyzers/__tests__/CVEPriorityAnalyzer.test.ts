import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { CVEPriorityAnalyzer } from "../CVEPriorityAnalyzer";
import { MITRE_MAPPINGS } from "../../attack/mitreMapping";
import type { AnalyzerInput } from "@/lib/pipeline/types";

describe("CVEPriorityAnalyzer", () => {
  const analyzer = new CVEPriorityAnalyzer();
  const config = analyzer.config;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns empty array when required evidence is missing", () => {
    const input: AnalyzerInput = {
      evidence: [],
      investigationId: "inv_123",
      target: "CVE-2023-1234",
      targetType: "CVE",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns LOW severity for CVSS below medium threshold (e.g. 3.9)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "cve_id", fact_value: "CVE-2023-1234", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "cvss_score", fact_value: config.thresholds.mediumCVSS - 0.1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "publish_date", fact_value: "2024-01-01T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "CVE",
      targetType: "CVE",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("LOW");
  });

  it("returns MEDIUM severity for CVSS exactly at medium threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "cve_id", fact_value: "CVE-2023-1234", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "cvss_score", fact_value: config.thresholds.mediumCVSS, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "publish_date", fact_value: "2024-01-01T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "CVE",
      targetType: "CVE",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].severity).toBe("MEDIUM");
  });

  it("returns HIGH severity for CVSS exactly at high threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "cve_id", fact_value: "CVE-2023-1234", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "cvss_score", fact_value: config.thresholds.highCVSS, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "publish_date", fact_value: "2024-01-01T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "CVE",
      targetType: "CVE",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].severity).toBe("HIGH");
  });

  it("returns CRITICAL severity for CVSS exactly at critical threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "cve_id", fact_value: "CVE-2023-1234", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "cvss_score", fact_value: config.thresholds.criticalCVSS, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "publish_date", fact_value: "2024-01-01T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "CVE",
      targetType: "CVE",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].severity).toBe("CRITICAL");
  });

  it("calculates confidence score and priority within bounds", () => {
    // 0 days old -> recency score 1.0. No exploit -> exploit bonus 0.0. CVSS 10.0 -> CVSS norm 1.0
    // Raw priority = 1.0 * 0.5 + 0.0 * 0.3 + 1.0 * 0.2 = 0.7
    // Score = 70. Confidence = min(50 + 70*0.5, 98) = min(85, 98) = 85
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "cve_id", fact_value: "CVE-2023-1234", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "cvss_score", fact_value: 10.0, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "publish_date", fact_value: "2024-01-01T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "CVE",
      targetType: "CVE",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].score_contribution).toBeLessThanOrEqual(20); // capped at 20
    expect(findings[0].confidence_score).toBe(85);
  });

  it("adds attack techniques based on mitreMapping", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "cve_id", fact_value: "CVE-2023-1234", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "cvss_score", fact_value: 10.0, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "publish_date", fact_value: "2024-01-01T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "CVE",
      targetType: "CVE",
    };
    const findings = analyzer.analyze(input);
    const expectedTechnique = "T1588.006";
    expect(findings[0].attack_techniques).toContain(expectedTechnique);
    expect(MITRE_MAPPINGS[expectedTechnique]).toBeDefined();
  });

  it("includes correct evidence IDs", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "cve_id", fact_value: "CVE", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "cvss_score", fact_value: 10.0, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "publish_date", fact_value: "2024-01-01T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e4", fact_type: "has_known_exploit", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e5", fact_type: "in_cisa_kev", fact_value: false, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e6", fact_type: "description", fact_value: "desc", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_unrelated", fact_type: "unrelated", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "CVE",
      targetType: "CVE",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].evidence_ids).toEqual(expect.arrayContaining(["e1", "e2", "e3", "e4", "e5", "e6"]));
    expect(findings[0].evidence_ids).not.toContain("e_unrelated");
  });
});
