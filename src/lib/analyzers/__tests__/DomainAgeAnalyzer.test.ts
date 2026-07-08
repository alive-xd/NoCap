import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DomainAgeAnalyzer } from "../DomainAgeAnalyzer";
import { MITRE_MAPPINGS } from "../../attack/mitreMapping";
import type { AnalyzerInput } from "@/lib/pipeline/types";

describe("DomainAgeAnalyzer", () => {
  const analyzer = new DomainAgeAnalyzer();
  const config = analyzer.config;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-05-01T00:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns empty array when required evidence (registration_date) is missing", () => {
    const input: AnalyzerInput = {
      evidence: [],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns empty array when domain age is older than recentDaysFlag (e.g. 31 days)", () => {
    // 31 days before 2024-05-01 is 2024-03-31
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "registration_date", fact_value: "2024-03-31T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" }
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns MEDIUM severity for domain exactly at recentDaysFlag threshold (30 days)", () => {
    // 30 days before 2024-05-01 is 2024-04-01
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "registration_date", fact_value: "2024-04-01T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" }
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("MEDIUM");
    // At 30 days (half life), score should be 50% of maxScore (15), so 7.5 -> rounded to 8
    expect(findings[0].score_contribution).toBe(8);
  });

  it("returns HIGH severity for domain exactly at highDaysFlag threshold (7 days)", () => {
    // 7 days before 2024-05-01 is 2024-04-24
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "registration_date", fact_value: "2024-04-24T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" }
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].confidence_score).toBe(78); // From the if/else block
  });

  it("returns HIGH severity (with higher confidence) for domain exactly at criticalDaysFlag threshold (3 days)", () => {
    // 3 days before 2024-05-01 is 2024-04-28
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "registration_date", fact_value: "2024-04-28T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" }
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].confidence_score).toBe(85);
  });

  it("returns max score contribution for domain registered today (0 days)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "registration_date", fact_value: "2024-05-01T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" }
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].score_contribution).toBe(config.thresholds.maxScore);
  });

  it("adds attack techniques based on mitreMapping", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "registration_date", fact_value: "2024-04-28T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" }
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    const expectedTechnique = "T1583.001";
    expect(findings[0].attack_techniques).toContain(expectedTechnique);
    expect(MITRE_MAPPINGS[expectedTechnique]).toBeDefined();
  });

  it("includes correct evidence IDs", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e_reg", fact_type: "registration_date", fact_value: "2024-04-28T00:00:00Z", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_other", fact_type: "other_fact", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].evidence_ids).toEqual(["e_reg"]);
  });
});
