import { describe, it, expect } from "vitest";
import { CVEParser } from "../CVEParser";

describe("CVEParser", () => {
  const parser = new CVEParser();

  it("extracts all facts from a valid realistic CVE response with CVSS 3.1", () => {
    const raw = {
      cve: {
        id: "CVE-2023-1234",
        metrics: {
          cvssMetricV31: [
            {
              cvssData: {
                baseScore: 9.8,
              },
            },
          ],
        },
        descriptions: [
          { lang: "fr", value: "Description française" },
          { lang: "en", value: "A critical buffer overflow vulnerability." },
        ],
        published: "2023-01-01T00:00:00.000Z",
      },
      has_known_exploit: true,
      in_cisa_kev: true,
    };
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "cve_id", fact_value: "CVE-2023-1234" },
        { fact_type: "cvss_score", fact_value: 9.8 },
        { fact_type: "publish_date", fact_value: "2023-01-01T00:00:00.000Z" },
        { fact_type: "has_known_exploit", fact_value: true },
        { fact_type: "in_cisa_kev", fact_value: true },
        { fact_type: "description", fact_value: "A critical buffer overflow vulnerability." },
      ])
    );
    expect(facts).toHaveLength(6);
  });

  it("falls back to CVSS 3.0 or 2.0 if 3.1 is missing", () => {
    const rawV3 = {
      cve: {
        id: "CVE-2022-1111",
        metrics: {
          cvssMetricV30: [{ cvssData: { baseScore: 8.5 } }],
        },
      },
    };
    const factsV3 = parser.parse(rawV3);
    expect(factsV3.find((f) => f.fact_type === "cvss_score")?.fact_value).toBe(8.5);

    const rawV2 = {
      cve: {
        id: "CVE-2010-0000",
        metrics: {
          cvssMetricV2: [{ cvssData: { baseScore: 7.0 } }],
        },
      },
    };
    const factsV2 = parser.parse(rawV2);
    expect(factsV2.find((f) => f.fact_type === "cvss_score")?.fact_value).toBe(7.0);
  });

  it("handles missing or undefined optional fields gracefully, setting safe defaults", () => {
    const raw = {};
    const facts = parser.parse(raw);
    
    expect(facts.find(f => f.fact_type === "cve_id")?.fact_value).toBe("");
    expect(facts.find(f => f.fact_type === "cvss_score")?.fact_value).toBe(0);
    expect(facts.find(f => f.fact_type === "description")?.fact_value).toBe("");
    expect(facts.find(f => f.fact_type === "has_known_exploit")?.fact_value).toBe(false);
    expect(facts.find(f => f.fact_type === "in_cisa_kev")?.fact_value).toBe(false);
    expect(typeof facts.find(f => f.fact_type === "publish_date")?.fact_value).toBe("string");
  });

  it("handles malformed input safely without throwing", () => {
    const raw = {
      cve: {
        metrics: {
          cvssMetricV31: "not-an-array", // will be treated as string instead of array
        },
      },
    };
    
    // cvssMetricV31.length > 0 on a string checks string length, but index 0 won't have cvssData
    // The parser handles this gracefully via optional chaining `[0]?.cvssData?.baseScore`
    const facts = parser.parse(raw);
    expect(facts.find(f => f.fact_type === "cvss_score")?.fact_value).toBe(0);
  });
});
