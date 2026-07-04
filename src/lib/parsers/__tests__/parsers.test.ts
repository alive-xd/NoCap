import { VirusTotalParser } from "../VirusTotalParser";
import { AbuseIPDBParser } from "../AbuseIPDBParser";
import { DomainStringParser } from "../DomainStringParser";

describe("Triage Parsers Sanity Suite", () => {
  test("VirusTotalParser should extract malicious attributes correctly", () => {
    const parser = new VirusTotalParser();
    const mockPayload = {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: 15,
            suspicious: 1,
            harmless: 50,
            undetermined: 4,
          },
          reputation: -40,
          tags: ["botnet", "phishing"],
        },
      },
    };

    const result = parser.parse(mockPayload);

    const maliciousCount = result.find((f) => f.fact_type === "malicious_count");
    const reputation = result.find((f) => f.fact_type === "reputation");

    expect(maliciousCount?.fact_value).toBe(15);
    expect(reputation?.fact_value).toBe(-40);
  });

  test("AbuseIPDBParser should extract report counts and score details", () => {
    const parser = new AbuseIPDBParser();
    const mockPayload = {
      data: {
        abuseConfidenceScore: 88,
        totalReports: 212,
        isp: "M247 Ltd",
        countryCode: "GB",
      },
    };

    const result = parser.parse(mockPayload);

    const score = result.find((f) => f.fact_type === "abuse_confidence_score");
    const reports = result.find((f) => f.fact_type === "total_reports");

    expect(score?.fact_value).toBe(88);
    expect(reports?.fact_value).toBe(212);
  });

  test("DomainStringParser should verify shannon entropy boundary calculations", () => {
    const parser = new DomainStringParser();
    const mockPayload = {
      domain: "paypal-security-update.com",
    };

    const result = parser.parse(mockPayload);

    const sld = result.find((f) => f.fact_type === "sld");
    const entropy = result.find((f) => f.fact_type === "entropy_score");

    expect(sld?.fact_value).toBe("paypal-security-update");
    expect(typeof entropy?.fact_value).toBe("number");
  });
});
