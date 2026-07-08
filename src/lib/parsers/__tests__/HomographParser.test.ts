import { describe, it, expect } from "vitest";
import { HomographParser, levenshtein, BRAND_LIST } from "../HomographParser";

describe("HomographParser", () => {
  const parser = new HomographParser();

  describe("levenshtein helper", () => {
    it("computes standard distance correctly", () => {
      expect(levenshtein("kitten", "sitting")).toBe(3);
      expect(levenshtein("paypal", "paypal")).toBe(0);
      expect(levenshtein("", "abc")).toBe(3);
      expect(levenshtein("abc", "")).toBe(3);
    });
  });

  it("extracts facts for a legitimate domain (distance 0)", () => {
    const raw = { domain: "paypal.com" };
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "input_domain", fact_value: "paypal.com" },
        { fact_type: "input_sld", fact_value: "paypal" },
        { fact_type: "closest_brand", fact_value: "paypal" },
        { fact_type: "closest_distance", fact_value: 0 },
      ])
    );
    expect(facts.find(f => f.fact_type === "all_candidates")?.fact_value).toEqual(
      expect.arrayContaining([
        { brand: "paypal", distance: 0 }
      ])
    );
  });

  it("detects a homograph impersonation using visual substitutions", () => {
    // "payrnent" normalizes to "payment" which doesn't exist in BRAND_LIST,
    // let's use "paypa1" -> normalizes to "paypal", distance 0 after normalization
    const raw = { domain: "paypa1.com" };
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "closest_brand", fact_value: "paypal" },
        { fact_type: "closest_distance", fact_value: 0 },
      ])
    );
  });

  it("handles a brand with a small typo (Levenshtein distance <= 3 without homographs)", () => {
    const raw = { domain: "microsft.com" }; // missing 'o' -> distance 1
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "closest_brand", fact_value: "microsoft" },
        { fact_type: "closest_distance", fact_value: 1 },
      ])
    );
  });

  it("returns distance 99 for unrelated domains with no close brand", () => {
    const raw = { domain: "completely-unrelated-random-domain.org" };
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "closest_distance", fact_value: 99 },
      ])
    );
    expect(facts.find(f => f.fact_type === "closest_brand")).toBeUndefined();
    expect(facts.find(f => f.fact_type === "all_candidates")).toBeUndefined();
  });

  it("handles missing or undefined domain gracefully", () => {
    const facts = parser.parse({});
    expect(facts).toEqual([]);
    
    expect(() => parser.parse(null as unknown as Record<string, unknown>)).toThrowError(TypeError);
  });

  it("handles extremely short SLDs gracefully", () => {
    const raw = { domain: "a.com" }; // SLD is "a"
    const facts = parser.parse(raw);
    
    // Distance to shortest brand (e.g. 'irs' length 3) might be 2, which is <= 3
    // So it might return closest_distance <= 3
    const distFact = facts.find(f => f.fact_type === "closest_distance")?.fact_value;
    expect(typeof distFact).toBe("number");
  });

  it("normalizes complex substitutions", () => {
    // vv -> w, 3 -> e, 1 -> l, l -> l, s -> s, f -> f, @ -> a, r -> r, g -> g, 0 -> o
    // vv3llsf@rg0 -> wellsfargo
    const raw = { domain: "vv3llsf@rg0.com" };
    const facts = parser.parse(raw);

    expect(facts.find(f => f.fact_type === "closest_brand")?.fact_value).toBe("wellsfargo");
    // After normalization to "wellsfargo", distance to "wellsfargo" is 0
    expect(facts.find(f => f.fact_type === "closest_distance")?.fact_value).toBe(0);
  });
});
