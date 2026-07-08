import { describe, it, expect } from "vitest";
import { computeScore } from "../scoring";
import type { Finding, ScoringProfile } from "@/lib/pipeline/types";

describe("scoring - computeScore", () => {
  const dummyProfile: ScoringProfile = {
    name: "v1.0",
    version: "1.0",
    enabled: true,
    source_weights: {},
  };

  const createFinding = (generated_by: string, claim: string, score_contribution: number, extra: Partial<Finding> = {}): Finding => ({
    generated_by,
    claim,
    score_contribution,
    severity: "MEDIUM",
    confidence_score: 50,
    evidence_ids: [],
    reasoning: "",
    ...extra,
  });

  it("computes a normal weighted sum", () => {
    const findings = [
      createFinding("SourceA", "Claim 1", 20),
      createFinding("SourceB", "Claim 2", 30),
    ];
    const result = computeScore(findings, dummyProfile, 2, 2);
    expect(result.rawSum).toBe(50);
    expect(result.finalScore).toBe(50);
    expect(result.degradationFactor).toBe(1);
    expect(result.breakdown).toHaveLength(2);
  });

  it("clamps when rawSum > 100 or < 0", () => {
    const findingsHigh = [createFinding("A", "C1", 120)];
    const resultHigh = computeScore(findingsHigh, dummyProfile, 1, 1);
    expect(resultHigh.rawSum).toBe(120);
    expect(resultHigh.finalScore).toBe(100);

    const findingsLow = [createFinding("A", "C1", -10)];
    const resultLow = computeScore(findingsLow, dummyProfile, 1, 1);
    expect(resultLow.rawSum).toBe(-10);
    expect(resultLow.finalScore).toBe(0);
  });

  it("deduplicates identical (generated_by, claim) pairs", () => {
    const findings = [
      createFinding("SourceA", "Claim X", 20),
      createFinding("SourceA", "Claim X", 20), // Duplicate
      createFinding("SourceB", "Claim X", 30), // Different source
    ];
    const result = computeScore(findings, dummyProfile, 1, 1);
    expect(result.rawSum).toBe(50);
    expect(result.breakdown).toHaveLength(2);
  });

  it("applies the sqrt(successful/total) degradation factor math at several ratios", () => {
    const findings = [createFinding("A", "C", 100)];

    // 1/1 ratio
    let res = computeScore(findings, dummyProfile, 1, 1);
    expect(res.degradationFactor).toBe(1);
    expect(res.finalScore).toBe(100);

    // 3/4 ratio = sqrt(0.75) ≈ 0.866
    res = computeScore(findings, dummyProfile, 3, 4);
    expect(res.degradationFactor).toBeCloseTo(Math.sqrt(0.75));
    expect(res.finalScore).toBe(Math.round(100 * Math.sqrt(0.75))); // 87

    // 1/4 ratio = sqrt(0.25) = 0.5
    res = computeScore(findings, dummyProfile, 1, 4);
    expect(res.degradationFactor).toBe(0.5);
    expect(res.finalScore).toBe(50);

    // 0 total sources (edge case)
    res = computeScore(findings, dummyProfile, 0, 0);
    expect(res.degradationFactor).toBe(1);
    expect(res.finalScore).toBe(100);
  });

  it("confirm attack_techniques or any other new metadata field on a Finding does NOT affect finalScore", () => {
    const findingsBase = [createFinding("A", "C", 50)];
    const resBase = computeScore(findingsBase, dummyProfile, 1, 1);

    const findingsExtra = [
      createFinding("A", "C", 50, { attack_techniques: ["T1588.006"], another_field: "value" } as unknown as Finding),
    ];
    const resExtra = computeScore(findingsExtra, dummyProfile, 1, 1);

    expect(resExtra.finalScore).toBe(resBase.finalScore);
    expect(resExtra.rawSum).toBe(resBase.rawSum);
    expect(resExtra.breakdown).toEqual(resBase.breakdown);
  });
});
