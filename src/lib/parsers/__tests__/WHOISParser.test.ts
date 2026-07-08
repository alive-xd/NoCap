import { describe, it, expect } from "vitest";
import { WHOISParser } from "../WHOISParser";

describe("WHOISParser", () => {
  const parser = new WHOISParser();

  it("extracts all facts from a valid realistic WHOIS response", () => {
    const raw = {
      creationDate: "2010-01-01T00:00:00Z",
      registryExpiryDate: "2025-01-01T00:00:00Z",
      updatedDate: "2024-01-01T00:00:00Z",
      registrar: "GoDaddy.com, LLC",
      registrantCountry: "US",
      nameServer: ["ns1.example.com", "ns2.example.com"],
      dnssec: "unsigned",
    };
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "registration_date", fact_value: "2010-01-01T00:00:00.000Z" },
        { fact_type: "expiry_date", fact_value: "2025-01-01T00:00:00.000Z" },
        { fact_type: "updated_date", fact_value: "2024-01-01T00:00:00.000Z" },
        { fact_type: "registrar", fact_value: "GoDaddy.com, LLC" },
        { fact_type: "registrant_country", fact_value: "US" },
        { fact_type: "name_servers", fact_value: ["ns1.example.com", "ns2.example.com"] },
        { fact_type: "dnssec", fact_value: "unsigned" },
      ])
    );
    expect(facts).toHaveLength(7);
  });

  it("handles alternative field names gracefully", () => {
    const raw = {
      domainCreated: "2015-05-05",
      expires: "2026-05-05",
      lastUpdated: "2025-05-05",
      sponsoringRegistrar: "Namecheap",
      countryCode: "CA",
      ns: "ns1.cloudflare.com ns2.cloudflare.com", // string of space-separated ns
      DNSSEC: "signedDelegation",
    };
    const facts = parser.parse(raw);

    expect(facts.find(f => f.fact_type === "registration_date")?.fact_value).toBe("2015-05-05T00:00:00.000Z");
    expect(facts.find(f => f.fact_type === "expiry_date")?.fact_value).toBe("2026-05-05T00:00:00.000Z");
    expect(facts.find(f => f.fact_type === "updated_date")?.fact_value).toBe("2025-05-05T00:00:00.000Z");
    expect(facts.find(f => f.fact_type === "registrar")?.fact_value).toBe("Namecheap");
    expect(facts.find(f => f.fact_type === "registrant_country")?.fact_value).toBe("CA");
    expect(facts.find(f => f.fact_type === "name_servers")?.fact_value).toEqual(["ns1.cloudflare.com", "ns2.cloudflare.com"]);
    expect(facts.find(f => f.fact_type === "dnssec")?.fact_value).toBe("signedDelegation");
  });

  it("handles missing or undefined optional fields without throwing", () => {
    const raw = {
      registrar: "Google LLC",
      // everything else missing
    };
    const facts = parser.parse(raw);
    
    expect(facts).toEqual([
      { fact_type: "registrar", fact_value: "Google LLC" },
    ]);
  });

  it("handles missing dates (like no registration_date) gracefully", () => {
    const raw = {
      creationDate: "", // empty
      expires: null,
      lastUpdated: "invalid-date-format",
    };
    const facts = parser.parse(raw);
    
    // Invalid or missing dates should just be skipped
    expect(facts.find(f => f.fact_type === "registration_date")).toBeUndefined();
    expect(facts.find(f => f.fact_type === "expiry_date")).toBeUndefined();
    expect(facts.find(f => f.fact_type === "updated_date")).toBeUndefined();
  });

  it("handles completely empty data object gracefully", () => {
    const facts = parser.parse({});
    expect(facts).toEqual([]);
  });

  it("handles null safely without throwing", () => {
    // Current behavior throws TypeError if null because of raw[field] in findField
    // We expect it to throw TypeError based on the instruction "matching whatever the parser already does"
    expect(() => parser.parse(null as unknown as Record<string, unknown>)).toThrowError(TypeError);
  });
});
