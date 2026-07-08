import { describe, it, expect } from "vitest";
import { SubdomainParser } from "../SubdomainParser";

describe("SubdomainParser", () => {
  const parser = new SubdomainParser();

  it("extracts all facts from a valid realistic crt.sh response", () => {
    const raw = {
      subdomains: ["test.example.com", "api.example.com"],
      entries: [
        {
          issuer_name: "C=US, O=Let's Encrypt, CN=R3",
          common_name: "test.example.com",
          name_value: "test.example.com",
          not_before: "2023-01-01T00:00:00Z",
        },
        {
          issuer_name: "C=US, O=DigiCert Inc, CN=DigiCert Global Root CA",
          common_name: "*.example.com",
          name_value: "*.example.com\napi.example.com",
          not_before: "2022-01-01T00:00:00Z",
        },
      ],
    };
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "subdomain_list", fact_value: ["test.example.com", "api.example.com"] },
        { fact_type: "subdomain_count", fact_value: 2 },
        { fact_type: "wildcard_detected", fact_value: true }, // because of *.example.com
        { fact_type: "earliest_cert", fact_value: "2022-01-01T00:00:00.000Z" },
        { fact_type: "latest_cert", fact_value: "2023-01-01T00:00:00.000Z" },
        { fact_type: "unique_issuers", fact_value: ["R3", "DigiCert Global Root CA"] },
      ])
    );
    expect(facts).toHaveLength(6);
  });

  it("handles missing entries or subdomains arrays gracefully by returning empty array", () => {
    const factsNoEntries = parser.parse({ subdomains: ["test.com"] });
    expect(factsNoEntries).toEqual([]);

    const factsNoSubdomains = parser.parse({ entries: [] });
    expect(factsNoSubdomains).toEqual([]);

    const factsEmpty = parser.parse({});
    expect(factsEmpty).toEqual([]);

    expect(() => parser.parse(null as unknown as Record<string, unknown>)).toThrowError(TypeError);
  });

  it("handles empty arrays", () => {
    const raw = { subdomains: [], entries: [] };
    const facts = parser.parse(raw);
    
    expect(facts).toEqual([
      { fact_type: "subdomain_list", fact_value: [] },
      { fact_type: "subdomain_count", fact_value: 0 },
      { fact_type: "wildcard_detected", fact_value: false },
    ]);
  });

  it("handles invalid or missing dates safely", () => {
    const raw = {
      subdomains: ["a.com"],
      entries: [
        { common_name: "a.com" }, // no not_before
        { common_name: "b.com", not_before: "invalid-date-string" },
      ],
    };
    const facts = parser.parse(raw);
    
    // Should skip invalid dates entirely and not produce earliest_cert/latest_cert
    expect(facts.find(f => f.fact_type === "earliest_cert")).toBeUndefined();
    expect(facts.find(f => f.fact_type === "latest_cert")).toBeUndefined();
  });
});
