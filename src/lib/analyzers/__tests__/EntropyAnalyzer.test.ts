import { describe, it, expect } from "vitest";
import { EntropyAnalyzer } from "../EntropyAnalyzer";
import { MITRE_MAPPINGS } from "../../attack/mitreMapping";
import type { AnalyzerInput } from "@/lib/pipeline/types";

describe("EntropyAnalyzer", () => {
  const analyzer = new EntropyAnalyzer();
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

  it("returns empty array when entropy is below threshold (e.g. 3.8)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "entropy_score", fact_value: config.thresholds.entropyFlag - 0.1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "sld_length", fact_value: config.thresholds.minSldLength, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns empty array when SLD length is below minimum (e.g. 4)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "entropy_score", fact_value: config.thresholds.entropyFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "sld_length", fact_value: config.thresholds.minSldLength - 1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "a.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns MEDIUM severity for entropy exactly at threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "entropy_score", fact_value: config.thresholds.entropyFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "sld_length", fact_value: config.thresholds.minSldLength, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "consonant_ratio", fact_value: 0.5, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "domain.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("MEDIUM");
    expect(findings[0].confidence_score).toBe(55);
  });

  it("returns HIGH severity for entropy exactly at high entropy threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "entropy_score", fact_value: config.thresholds.highEntropyFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "sld_length", fact_value: config.thresholds.minSldLength, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "consonant_ratio", fact_value: 0.5, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "domain.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].confidence_score).toBe(70); // 55 + 15
  });

  it("adds confidence for high digit ratio exactly at threshold", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "entropy_score", fact_value: config.thresholds.entropyFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "sld_length", fact_value: config.thresholds.minSldLength, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "digit_ratio", fact_value: config.thresholds.highDigitRatioFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e4", fact_type: "consonant_ratio", fact_value: 0.5, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "domain.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].confidence_score).toBe(65); // 55 + 10
  });

  it("adds confidence for low consonant ratio", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "entropy_score", fact_value: config.thresholds.entropyFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "sld_length", fact_value: config.thresholds.minSldLength, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "consonant_ratio", fact_value: 0.49, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "domain.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].confidence_score).toBe(63); // 55 + 8
  });

  it("caps confidence at 95 and score at 15", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "entropy_score", fact_value: 10, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "sld_length", fact_value: 20, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "digit_ratio", fact_value: 1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e4", fact_type: "consonant_ratio", fact_value: 0, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "domain.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].confidence_score).toBe(88);
    expect(findings[0].score_contribution).toBe(15);
  });

  it("adds attack techniques based on mitreMapping", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "entropy_score", fact_value: config.thresholds.entropyFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "sld_length", fact_value: config.thresholds.minSldLength, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "domain.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    const expectedTechnique = "T1568.002";
    expect(findings[0].attack_techniques).toContain(expectedTechnique);
    expect(MITRE_MAPPINGS[expectedTechnique]).toBeDefined();
  });

  it("includes correct evidence IDs", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e_entropy", fact_type: "entropy_score", fact_value: config.thresholds.entropyFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_len", fact_type: "sld_length", fact_value: config.thresholds.minSldLength, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_other", fact_type: "other", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "domain.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].evidence_ids).toEqual(expect.arrayContaining(["e_entropy", "e_len"]));
    expect(findings[0].evidence_ids).not.toContain("e_other");
  });
});
