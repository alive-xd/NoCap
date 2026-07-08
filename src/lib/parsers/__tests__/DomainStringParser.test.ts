import { describe, it, expect } from "vitest";
import { DomainStringParser, shannonEntropy } from "../DomainStringParser";

describe("DomainStringParser", () => {
  const parser = new DomainStringParser();

  describe("shannonEntropy helper", () => {
    it("returns 0 for empty strings", () => {
      expect(shannonEntropy("")).toBe(0);
    });

    it("calculates entropy correctly for known strings", () => {
      // all same char = 0 entropy
      expect(shannonEntropy("aaaaa")).toBe(0);
      
      // 'ab' -> equal probability -> 1.0 entropy
      expect(shannonEntropy("ab")).toBe(1);
    });
  });

  it("extracts all facts from a valid domain", () => {
    const raw = { domain: "google.com" };
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "domain_string", fact_value: "google.com" },
        { fact_type: "sld", fact_value: "google" },
        { fact_type: "tld", fact_value: "com" },
        { fact_type: "entropy_score", fact_value: 1.92 }, // entropy of 'google'
        { fact_type: "label_count", fact_value: 2 },
        { fact_type: "sld_length", fact_value: 6 },
        { fact_type: "digit_ratio", fact_value: 0 },
        { fact_type: "consonant_ratio", fact_value: 0.5 }, // g, g, l (3/6)
      ])
    );
    expect(facts).toHaveLength(8);
  });

  it("handles subdomains by extracting the second-to-last label as SLD", () => {
    const raw = { domain: "mail.google.com" };
    const facts = parser.parse(raw);
    
    expect(facts.find(f => f.fact_type === "sld")?.fact_value).toBe("google");
    expect(facts.find(f => f.fact_type === "tld")?.fact_value).toBe("com");
    expect(facts.find(f => f.fact_type === "label_count")?.fact_value).toBe(3);
  });

  it("handles extremely short SLDs", () => {
    const raw = { domain: "t.co" };
    const facts = parser.parse(raw);
    
    expect(facts.find(f => f.fact_type === "sld")?.fact_value).toBe("t");
    expect(facts.find(f => f.fact_type === "entropy_score")?.fact_value).toBe(0); // 't' has 0 entropy
  });

  it("handles trailing dots (FQDNs)", () => {
    const raw = { domain: "example.com." };
    const facts = parser.parse(raw);
    
    expect(facts.find(f => f.fact_type === "sld")?.fact_value).toBe("example");
    expect(facts.find(f => f.fact_type === "tld")?.fact_value).toBe("com");
    expect(facts.find(f => f.fact_type === "label_count")?.fact_value).toBe(2);
  });

  it("handles single-label domains (no TLD)", () => {
    const raw = { domain: "localhost" };
    const facts = parser.parse(raw);
    
    expect(facts.find(f => f.fact_type === "sld")?.fact_value).toBe("localhost");
    expect(facts.find(f => f.fact_type === "tld")?.fact_value).toBe("");
    expect(facts.find(f => f.fact_type === "label_count")?.fact_value).toBe(1);
  });

  it("handles missing or undefined domain gracefully", () => {
    const facts = parser.parse({});
    expect(facts).toEqual([]);
    
    expect(() => parser.parse(null as unknown as Record<string, unknown>)).toThrowError(TypeError);
  });

  it("calculates digit ratio and consonant ratio correctly", () => {
    const raw = { domain: "a1b2c3d4.net" };
    const facts = parser.parse(raw);
    
    // a1b2c3d4 is 8 chars, 4 digits, 4 letters (b, c, d are consonants, a is vowel)
    expect(facts.find(f => f.fact_type === "digit_ratio")?.fact_value).toBe(0.5); // 4/8
    expect(facts.find(f => f.fact_type === "consonant_ratio")?.fact_value).toBe(0.38); // 3/8 = 0.375 -> rounded to 0.38
  });
});
