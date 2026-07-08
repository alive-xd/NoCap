import { describe, it, expect } from "vitest";
import { ASNLookupParser } from "../ASNLookupParser";

describe("ASNLookupParser", () => {
  const parser = new ASNLookupParser();

  it("extracts all facts from a valid realistic ip-api response", () => {
    const raw = {
      status: "success",
      country: "United States",
      countryCode: "US",
      isp: "Google LLC",
      org: "Google Public DNS",
      as: "AS15169 Google LLC",
      query: "8.8.8.8",
    };
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "ip", fact_value: "8.8.8.8" },
        { fact_type: "asn", fact_value: "AS15169 Google LLC" },
        { fact_type: "asn_number", fact_value: 15169 },
        { fact_type: "org", fact_value: "Google Public DNS" },
        { fact_type: "isp", fact_value: "Google LLC" },
        { fact_type: "country", fact_value: "United States" },
        { fact_type: "country_code", fact_value: "US" },
      ])
    );
    expect(facts).toHaveLength(7);
  });

  it("handles missing or undefined optional fields without throwing", () => {
    const raw = {
      status: "success",
      query: "127.0.0.1",
      // missing country, as, org, etc.
    };
    const facts = parser.parse(raw);
    
    expect(facts).toEqual([
      { fact_type: "ip", fact_value: "127.0.0.1" },
    ]);
  });

  it("handles an empty response body", () => {
    const raw = {};
    const facts = parser.parse(raw);
    
    expect(facts).toEqual([]);
  });

  it("handles a malformed asn string gracefully (no asn_number extracted)", () => {
    const raw = {
      as: "Google LLC", // missing the 'AS1234' prefix
    };
    const facts = parser.parse(raw);
    
    expect(facts).toEqual([
      { fact_type: "asn", fact_value: "Google LLC" },
    ]);
    // It should not extract asn_number
    expect(facts.find(f => f.fact_type === "asn_number")).toBeUndefined();
  });

  it("handles completely malformed input safely or by throwing appropriately", () => {
    // Current behavior throws on null since it checks data.query directly
    expect(() => parser.parse(null as unknown as Record<string, unknown>)).toThrowError(TypeError);

    // Current behavior handles strings by treating them as objects which have undefined properties
    const factsWithString = parser.parse("unexpected" as unknown as Record<string, unknown>);
    expect(factsWithString).toEqual([]);
  });
});
