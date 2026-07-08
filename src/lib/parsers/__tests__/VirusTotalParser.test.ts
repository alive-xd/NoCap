import { describe, it, expect } from "vitest";
import { VirusTotalParser } from "../VirusTotalParser";

describe("VirusTotalParser", () => {
  const parser = new VirusTotalParser();

  it("extracts all facts from a valid realistic VirusTotal response", () => {
    const raw = {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: 4,
            suspicious: 1,
            undetected: 80,
            harmless: 5,
            timeout: 0,
          },
          last_analysis_results: {
            "Kaspersky": { category: "malicious", result: "Trojan" },
            "BitDefender": { category: "malicious", result: "Malware" },
            "Google Safebrowsing": { category: "undetected", result: "clean" },
          },
          tags: ["phishing", "malware"],
          categories: {
            "Forcepoint ThreatSeeker": "malicious web sites",
            "BitDefender": "malware",
          },
          reputation: -15,
        },
      },
    };
    
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "malicious_count", fact_value: 4 },
        { fact_type: "suspicious_count", fact_value: 1 },
        { fact_type: "undetected_count", fact_value: 80 },
        { fact_type: "vendor_count", fact_value: 90 }, // 4 + 1 + 80 + 5 + 0
        { fact_type: "tags", fact_value: ["phishing", "malware"] },
        { fact_type: "categories", fact_value: ["malicious web sites", "malware"] },
        { fact_type: "reputation", fact_value: -15 },
        { fact_type: "flagging_vendors", fact_value: ["Kaspersky", "BitDefender"] },
      ])
    );
    expect(facts).toHaveLength(8);
  });

  it("handles missing or undefined optional fields without throwing, supplying defaults", () => {
    const raw = {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: 2,
            // suspicious, undetected missing
          },
        },
      },
    };
    const facts = parser.parse(raw);
    
    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "malicious_count", fact_value: 2 },
        { fact_type: "suspicious_count", fact_value: 0 },
        { fact_type: "undetected_count", fact_value: 0 },
        { fact_type: "vendor_count", fact_value: 2 },
      ])
    );
    // tags, categories, reputation, flagging_vendors should be omitted since they are missing
    expect(facts.find(f => f.fact_type === "tags")).toBeUndefined();
    expect(facts.find(f => f.fact_type === "categories")).toBeUndefined();
    expect(facts.find(f => f.fact_type === "reputation")).toBeUndefined();
    expect(facts.find(f => f.fact_type === "flagging_vendors")).toBeUndefined();
  });

  it("handles completely empty data object gracefully", () => {
    const factsDataEmpty = parser.parse({ data: {} });
    expect(factsDataEmpty).toEqual([]);

    const factsAttrsEmpty = parser.parse({ data: { attributes: {} } });
    expect(factsAttrsEmpty).toEqual([
      { fact_type: "malicious_count", fact_value: 0 },
      { fact_type: "suspicious_count", fact_value: 0 },
      { fact_type: "undetected_count", fact_value: 0 },
      { fact_type: "vendor_count", fact_value: 0 },
    ]);
  });

  it("handles completely malformed input safely without throwing", () => {
    const factsEmpty = parser.parse({});
    expect(factsEmpty).toEqual([]);

    const factsNull = parser.parse(null as unknown as Record<string, unknown>);
    expect(factsNull).toEqual([]);
  });
});
