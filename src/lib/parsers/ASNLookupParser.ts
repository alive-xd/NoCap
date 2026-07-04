/**
 * ASNLookupParser v1.0
 *
 * Transforms a raw ip-api.com response into atomic Evidence facts.
 * No judgment — ASNReputationAnalyzer applies judgment.
 *
 * Extracted fact types:
 *   - asn          : ASN string (e.g. "AS15169")
 *   - asn_number   : numeric ASN (e.g. 15169)
 *   - org          : organization name
 *   - isp          : ISP name
 *   - country      : country name
 *   - country_code : 2-letter ISO country code
 *   - ip           : the queried IP address
 */

import type { Parser, ParsedEvidence } from "@/lib/pipeline/types";

interface IPAPIRaw {
  status?: string;
  country?: string;
  countryCode?: string;
  isp?: string;
  org?: string;
  as?: string;    // Format: "AS15169 Google LLC"
  query?: string;
}

export class ASNLookupParser implements Parser<Record<string, unknown>> {
  readonly name = "ASNLookupParser";
  readonly version = "1.0";

  parse(raw: Record<string, unknown>): ParsedEvidence[] {
    const facts: ParsedEvidence[] = [];
    const data = raw as IPAPIRaw;

    if (data.query) {
      facts.push({ fact_type: "ip", fact_value: data.query });
    }

    if (data.as) {
      facts.push({ fact_type: "asn", fact_value: data.as });

      // Extract numeric ASN from "AS15169 Google LLC"
      const match = data.as.match(/^AS(\d+)/);
      if (match) {
        facts.push({ fact_type: "asn_number", fact_value: parseInt(match[1], 10) });
      }
    }

    if (data.org) {
      facts.push({ fact_type: "org", fact_value: data.org });
    }
    if (data.isp) {
      facts.push({ fact_type: "isp", fact_value: data.isp });
    }
    if (data.country) {
      facts.push({ fact_type: "country", fact_value: data.country });
    }
    if (data.countryCode) {
      facts.push({ fact_type: "country_code", fact_value: data.countryCode });
    }

    return facts;
  }
}
