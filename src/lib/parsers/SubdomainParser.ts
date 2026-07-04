/**
 * SubdomainParser v1.0
 *
 * Transforms raw crt.sh CT log data into atomic Evidence facts.
 * Used by the Attack Surface investigation type.
 * No judgment — FingerprintAnalyzer applies judgment to the subdomains found.
 *
 * Extracted fact types:
 *   - subdomain_list    : array of discovered subdomain strings
 *   - subdomain_count   : total unique subdomains found
 *   - wildcard_detected : boolean — if wildcard certs exist (*.domain.com)
 *   - earliest_cert     : ISO date of oldest certificate found
 *   - latest_cert       : ISO date of most recent certificate found
 *   - unique_issuers    : array of CA names that issued certs
 */

import type { Parser, ParsedEvidence } from "@/lib/pipeline/types";

interface CrtShEntry {
  issuer_name?: string;
  common_name?: string;
  name_value?: string;
  not_before?: string;
  not_after?: string;
}

export class SubdomainParser implements Parser<Record<string, unknown>> {
  readonly name = "SubdomainParser";
  readonly version = "1.0";

  parse(raw: Record<string, unknown>): ParsedEvidence[] {
    const facts: ParsedEvidence[] = [];

    // raw is the full crt.sh response stored by the orchestrator
    const entries = raw["entries"] as CrtShEntry[] | undefined;
    const subdomains = raw["subdomains"] as string[] | undefined;

    if (!entries || !subdomains) return facts;

    facts.push({ fact_type: "subdomain_list", fact_value: subdomains });
    facts.push({ fact_type: "subdomain_count", fact_value: subdomains.length });

    // Check for wildcard certs
    const hasWildcard = entries.some(
      (e) =>
        e.common_name?.startsWith("*") ||
        e.name_value?.includes("*")
    );
    facts.push({ fact_type: "wildcard_detected", fact_value: hasWildcard });

    // Certificate date range
    const dates = entries
      .map((e) => e.not_before)
      .filter((d): d is string => !!d)
      .map((d) => new Date(d).getTime())
      .filter((t) => !isNaN(t));

    if (dates.length > 0) {
      facts.push({
        fact_type: "earliest_cert",
        fact_value: new Date(Math.min(...dates)).toISOString(),
      });
      facts.push({
        fact_type: "latest_cert",
        fact_value: new Date(Math.max(...dates)).toISOString(),
      });
    }

    // Unique issuers
    const issuers = [
      ...new Set(
        entries
          .map((e) => e.issuer_name)
          .filter((n): n is string => !!n)
          .map((n) => {
            // Extract CN from issuer DN: "CN=R10,O=Let's Encrypt,C=US"
            const cnMatch = n.match(/CN=([^,]+)/);
            return cnMatch ? cnMatch[1] : n;
          })
      ),
    ];
    if (issuers.length > 0) {
      facts.push({ fact_type: "unique_issuers", fact_value: issuers });
    }

    return facts;
  }
}
