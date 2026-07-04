/**
 * AbuseIPDBParser v1.0
 *
 * Transforms a raw AbuseIPDB API response into atomic Evidence facts.
 * No judgment — that belongs to AbuseIPDBAnalyzer.
 *
 * Extracted fact types:
 *   - abuse_confidence_score : 0-100 community abuse confidence
 *   - total_reports          : total abuse reports filed
 *   - country_code           : 2-letter ISO country code
 *   - isp                    : ISP name
 *   - usage_type             : e.g. "Data Center/Web Hosting/Transit"
 *   - domain                 : reverse-resolved domain if available
 *   - is_whitelisted         : boolean
 *   - is_tor                 : boolean (Tor exit node)
 */

import type { Parser, ParsedEvidence } from "@/lib/pipeline/types";

interface AbuseIPDBRaw {
  data?: {
    ipAddress?: string;
    isPublic?: boolean;
    ipVersion?: number;
    isWhitelisted?: boolean;
    abuseConfidenceScore?: number;
    countryCode?: string;
    usageType?: string;
    isp?: string;
    domain?: string;
    isTor?: boolean;
    totalReports?: number;
    numDistinctUsers?: number;
    lastReportedAt?: string | null;
  };
}

export class AbuseIPDBParser implements Parser<Record<string, unknown>> {
  readonly name = "AbuseIPDBParser";
  readonly version = "1.0";

  parse(raw: Record<string, unknown>): ParsedEvidence[] {
    const facts: ParsedEvidence[] = [];
    const data = (raw as AbuseIPDBRaw)?.data;
    if (!data) return facts;

    facts.push({
      fact_type: "abuse_confidence_score",
      fact_value: data.abuseConfidenceScore ?? 0,
    });
    facts.push({
      fact_type: "total_reports",
      fact_value: data.totalReports ?? 0,
    });

    if (data.countryCode) {
      facts.push({ fact_type: "country_code", fact_value: data.countryCode });
    }
    if (data.isp) {
      facts.push({ fact_type: "isp", fact_value: data.isp });
    }
    if (data.usageType) {
      facts.push({ fact_type: "usage_type", fact_value: data.usageType });
    }
    if (data.domain) {
      facts.push({ fact_type: "rdns_domain", fact_value: data.domain });
    }
    if (typeof data.isWhitelisted === "boolean") {
      facts.push({ fact_type: "is_whitelisted", fact_value: data.isWhitelisted });
    }
    if (typeof data.isTor === "boolean") {
      facts.push({ fact_type: "is_tor", fact_value: data.isTor });
    }
    if (data.lastReportedAt) {
      facts.push({ fact_type: "last_reported_at", fact_value: data.lastReportedAt });
    }

    return facts;
  }
}
