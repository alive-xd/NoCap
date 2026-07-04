/**
 * VirusTotalParser v1.0
 *
 * Transforms a raw VirusTotal API response (Artifact) into atomic Evidence facts.
 * NO judgment applied here — that is VirusTotalAnalyzer's job.
 *
 * Extracted fact types:
 *   - malicious_count      : number of vendors flagging as malicious
 *   - suspicious_count     : number of vendors flagging as suspicious
 *   - undetected_count     : number of vendors with clean result
 *   - vendor_count         : total vendors that scanned
 *   - tags                 : array of tags (e.g. ["phishing", "malware"])
 *   - categories           : vendor-supplied category strings
 *   - reputation           : VT community reputation score (-100 to 100)
 */

import type { Parser, ParsedEvidence } from "@/lib/pipeline/types";

export class VirusTotalParser implements Parser<Record<string, unknown>> {
  readonly name = "VirusTotalParser";
  readonly version = "1.0";

  parse(raw: Record<string, unknown>): ParsedEvidence[] {
    const facts: ParsedEvidence[] = [];
    const data = raw as {
      data?: {
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
            undetected?: number;
            harmless?: number;
            timeout?: number;
          };
          last_analysis_results?: Record<string, { category: string; result: string | null }>;
          tags?: string[];
          categories?: Record<string, string>;
          reputation?: number;
          total_votes?: { harmless: number; malicious: number };
        };
      };
    };

    const attrs = data?.data?.attributes;
    if (!attrs) return facts;

    const stats = attrs.last_analysis_stats ?? {};
    const maliciousCount = stats.malicious ?? 0;
    const suspiciousCount = stats.suspicious ?? 0;
    const undetectedCount = stats.undetected ?? 0;
    const harmlessCount = stats.harmless ?? 0;
    const timeoutCount = stats.timeout ?? 0;
    const vendorCount =
      maliciousCount +
      suspiciousCount +
      undetectedCount +
      harmlessCount +
      timeoutCount;

    facts.push({ fact_type: "malicious_count", fact_value: maliciousCount });
    facts.push({ fact_type: "suspicious_count", fact_value: suspiciousCount });
    facts.push({ fact_type: "undetected_count", fact_value: undetectedCount });
    facts.push({ fact_type: "vendor_count", fact_value: vendorCount });

    if (attrs.tags && attrs.tags.length > 0) {
      facts.push({ fact_type: "tags", fact_value: attrs.tags });
    }

    if (attrs.categories) {
      const categoryValues = Object.values(attrs.categories).filter(Boolean);
      if (categoryValues.length > 0) {
        facts.push({ fact_type: "categories", fact_value: categoryValues });
      }
    }

    if (typeof attrs.reputation === "number") {
      facts.push({ fact_type: "reputation", fact_value: attrs.reputation });
    }

    // Extract which vendors flagged it — stored as a fact for drill-down transparency
    if (attrs.last_analysis_results) {
      const flaggingVendors = Object.entries(attrs.last_analysis_results)
        .filter(([, r]) => r.category === "malicious")
        .map(([vendor]) => vendor);
      if (flaggingVendors.length > 0) {
        facts.push({ fact_type: "flagging_vendors", fact_value: flaggingVendors });
      }
    }

    return facts;
  }
}
