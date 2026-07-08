import { describe, it, expect } from "vitest";
import { AbuseIPDBParser } from "../AbuseIPDBParser";

describe("AbuseIPDBParser", () => {
  const parser = new AbuseIPDBParser();

  it("extracts all facts from a valid realistic AbuseIPDB response", () => {
    const raw = {
      data: {
        ipAddress: "118.25.6.39",
        isPublic: true,
        ipVersion: 4,
        isWhitelisted: false,
        abuseConfidenceScore: 100,
        countryCode: "CN",
        usageType: "Data Center/Web Hosting/Transit",
        isp: "Tencent Cloud Computing (Beijing) Co., Ltd",
        domain: "tencent.com",
        isTor: false,
        totalReports: 15,
        numDistinctUsers: 5,
        lastReportedAt: "2024-05-15T12:00:00Z",
      },
    };
    const facts = parser.parse(raw);

    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "abuse_confidence_score", fact_value: 100 },
        { fact_type: "total_reports", fact_value: 15 },
        { fact_type: "country_code", fact_value: "CN" },
        { fact_type: "isp", fact_value: "Tencent Cloud Computing (Beijing) Co., Ltd" },
        { fact_type: "usage_type", fact_value: "Data Center/Web Hosting/Transit" },
        { fact_type: "rdns_domain", fact_value: "tencent.com" },
        { fact_type: "is_whitelisted", fact_value: false },
        { fact_type: "is_tor", fact_value: false },
        { fact_type: "last_reported_at", fact_value: "2024-05-15T12:00:00Z" },
      ])
    );
    expect(facts).toHaveLength(9);
  });

  it("handles missing or undefined optional fields without throwing (uses defaults for scores)", () => {
    const raw = {
      data: {
        ipAddress: "127.0.0.1",
        // missing scores and other optional info
      },
    };
    const facts = parser.parse(raw);
    
    expect(facts).toEqual(
      expect.arrayContaining([
        { fact_type: "abuse_confidence_score", fact_value: 0 },
        { fact_type: "total_reports", fact_value: 0 },
      ])
    );
    expect(facts).toHaveLength(2);
  });

  it("handles an empty response body or missing data object gracefully", () => {
    const factsEmptyData = parser.parse({ data: {} });
    expect(factsEmptyData).toEqual([
      { fact_type: "abuse_confidence_score", fact_value: 0 },
      { fact_type: "total_reports", fact_value: 0 },
    ]);

    const factsNoData = parser.parse({});
    expect(factsNoData).toEqual([]);
  });

  it("handles malformed input safely", () => {
    const factsNull = parser.parse(null as unknown as Record<string, unknown>);
    expect(factsNull).toEqual([]);

    const factsDataNull = parser.parse({ data: null });
    expect(factsDataNull).toEqual([]);
  });
});
