import { describe, it, expect } from "vitest";
import { HomographAnalyzer } from "../HomographAnalyzer";
import { MITRE_MAPPINGS } from "../../attack/mitreMapping";
import type { AnalyzerInput } from "@/lib/pipeline/types";

describe("HomographAnalyzer", () => {
  const analyzer = new HomographAnalyzer();
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

  it("returns empty array when closest_distance is above extended threshold (e.g. 4)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "closest_distance", fact_value: config.thresholds.extendedDistanceFlag + 1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns MEDIUM severity for distance exactly at extended threshold (3)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "closest_distance", fact_value: config.thresholds.extendedDistanceFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("MEDIUM");
    expect(findings[0].confidence_score).toBe(55);
    expect(findings[0].score_contribution).toBe(10);
  });

  it("returns HIGH severity for distance exactly at distanceFlag threshold (2)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "closest_distance", fact_value: config.thresholds.distanceFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].confidence_score).toBe(80);
    expect(findings[0].score_contribution).toBe(20);
  });

  it("returns HIGH severity for distance below distanceFlag threshold (1)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "closest_distance", fact_value: config.thresholds.distanceFlag - 1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("HIGH");
  });

  it("adds attack techniques based on mitreMapping", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "closest_distance", fact_value: config.thresholds.distanceFlag, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
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
        { id: "e_dist", fact_type: "closest_distance", fact_value: 1, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_brand", fact_type: "closest_brand", fact_value: "paypal", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_domain", fact_type: "input_domain", fact_value: "paypa1.com", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_sld", fact_type: "input_sld", fact_value: "paypa1", artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_cands", fact_type: "all_candidates", fact_value: ["paypal"], artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e_other", fact_type: "other", fact_value: true, artifact_id: "a", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv",
      target: "example.com",
      targetType: "DOMAIN",
    };
    const findings = analyzer.analyze(input);
    expect(findings[0].evidence_ids).toEqual(expect.arrayContaining([
      "e_dist", "e_brand", "e_domain", "e_sld", "e_cands"
    ]));
    expect(findings[0].evidence_ids).not.toContain("e_other");
  });
});
