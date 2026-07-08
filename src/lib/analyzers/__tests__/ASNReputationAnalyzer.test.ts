import { describe, it, expect } from "vitest";
import { ASNReputationAnalyzer } from "../ASNReputationAnalyzer";
import { MITRE_MAPPINGS } from "../../attack/mitreMapping";
import type { AnalyzerInput } from "@/lib/pipeline/types";

describe("ASNReputationAnalyzer", () => {
  const analyzer = new ASNReputationAnalyzer();
  const config = analyzer.config;

  it("returns empty array when required evidence (asn_number) is missing", () => {
    const input: AnalyzerInput = {
      evidence: [],
      investigationId: "inv_123",
      target: "1.1.1.1",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns empty array for an ASN that is not on the abusive list", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "asn_number", fact_value: 15169, artifact_id: "a1", parser_name: "p", parser_version: "1", created_at: "" }
      ],
      investigationId: "inv_123",
      target: "8.8.8.8",
      targetType: "IP",
    };
    const findings = analyzer.analyze(input);
    expect(findings).toEqual([]);
  });

  it("returns HIGH severity and tier1 score for a Tier 1 ASN (e.g. 9009)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e1", fact_type: "asn_number", fact_value: 9009, artifact_id: "a1", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e2", fact_type: "asn", fact_value: "AS9009", artifact_id: "a1", parser_name: "p", parser_version: "1", created_at: "" },
        { id: "e3", fact_type: "org", fact_value: "M247 Ltd", artifact_id: "a1", parser_name: "p", parser_version: "1", created_at: "" },
      ],
      investigationId: "inv_123",
      target: "1.2.3.4",
      targetType: "IP",
    };
    
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    
    const finding = findings[0];
    expect(finding.severity).toBe("HIGH");
    expect(finding.score_contribution).toBe(config.thresholds.tier1ScoreContribution);
    expect(finding.confidence_score).toBe(75);
    
    // Check evidence IDs
    expect(finding.evidence_ids).toEqual(expect.arrayContaining(["e1", "e2", "e3"]));
    expect(finding.evidence_ids).toHaveLength(3);
    
    // Check attack techniques (M247 Ltd is 'server' so T1583.004)
    expect(finding.attack_techniques).toBeDefined();
    expect(finding.attack_techniques).toContain(MITRE_MAPPINGS["T1583.004"].techniqueId);
  });

  it("returns MEDIUM severity and tier2 score for a Tier 2 ASN (e.g. 16276)", () => {
    const input: AnalyzerInput = {
      evidence: [
        { id: "e_asn", fact_type: "asn_number", fact_value: 16276, artifact_id: "a1", parser_name: "p", parser_version: "1", created_at: "" }
      ],
      investigationId: "inv_123",
      target: "5.6.7.8",
      targetType: "IP",
    };
    
    const findings = analyzer.analyze(input);
    expect(findings).toHaveLength(1);
    
    const finding = findings[0];
    expect(finding.severity).toBe("MEDIUM");
    expect(finding.score_contribution).toBe(config.thresholds.tier2ScoreContribution);
    expect(finding.confidence_score).toBe(55);
    
    // Only e_asn was provided in the input, so only that should be in evidence_ids
    expect(finding.evidence_ids).toEqual(["e_asn"]);
    
    // Check attack techniques (OVH is 'vps' so T1583.003)
    expect(finding.attack_techniques).toBeDefined();
    expect(finding.attack_techniques).toContain(MITRE_MAPPINGS["T1583.003"].techniqueId);
  });
});
