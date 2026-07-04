/**
 * DomainStringParser v1.0
 *
 * Computes structural properties of a domain string, including Shannon
 * entropy. This is a purely computational parser — no external API calls.
 *
 * The entropy calculation is implemented here directly (no library):
 *
 *   H = -Σ p(c) * log2(p(c))   for each unique character c in the string
 *
 * where p(c) = count(c) / length(string)
 *
 * Rationale for using the second-level domain (SLD) only:
 * We strip the TLD before computing entropy because TLDs follow predictable
 * patterns (.com, .net) and would lower entropy artificially for DGA domains
 * that use unusual TLDs. The registrable label is the meaningful unit.
 *
 * Extracted fact types:
 *   - domain_string    : the full input domain
 *   - sld              : second-level domain label (e.g. "google" from "google.com")
 *   - entropy_score    : Shannon entropy of the SLD (float, 2 decimal places)
 *   - tld              : top-level domain
 *   - label_count      : number of DNS labels (dots + 1)
 *   - sld_length       : character count of the SLD
 *   - digit_ratio      : fraction of digits in the SLD (DGA signal)
 *   - consonant_ratio  : fraction of consonants (low ratio = random-looking)
 */

import type { Parser, ParsedEvidence } from "@/lib/pipeline/types";

/**
 * Computes Shannon entropy of a string.
 * Returns 0 for empty strings.
 */
export function shannonEntropy(s: string): number {
  if (!s || s.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const char of s) {
    freq[char] = (freq[char] ?? 0) + 1;
  }

  let entropy = 0;
  const len = s.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Math.round(entropy * 100) / 100;
}

/**
 * Strips the TLD and returns the registrable second-level domain label.
 * Simple approach: take the second-to-last part when split by ".".
 * Does not handle multi-part TLDs (.co.uk) — acceptable for V1.
 */
function extractSLD(domain: string): { sld: string; tld: string } {
  // Remove trailing dot (FQDN)
  const cleaned = domain.replace(/\.$/, "").toLowerCase();
  const parts = cleaned.split(".");

  if (parts.length === 1) return { sld: cleaned, tld: "" };
  if (parts.length === 2) return { sld: parts[0], tld: parts[1] };

  // For subdomains like mail.google.com, extract "google" and "com"
  return {
    sld: parts[parts.length - 2],
    tld: parts[parts.length - 1],
  };
}

const CONSONANTS = new Set("bcdfghjklmnpqrstvwxyz");

export class DomainStringParser implements Parser<Record<string, unknown>> {
  readonly name = "DomainStringParser";
  readonly version = "1.0";

  /**
   * For DomainStringParser, raw is a synthetic object produced by the
   * orchestrator (no external API — it's a computed artifact).
   * Expected shape: { domain: string }
   */
  parse(raw: Record<string, unknown>): ParsedEvidence[] {
    const facts: ParsedEvidence[] = [];
    const domain = typeof raw["domain"] === "string" ? raw["domain"] : "";
    if (!domain) return facts;

    const { sld, tld } = extractSLD(domain);
    const entropy = shannonEntropy(sld);
    const labelCount = domain.replace(/\.$/, "").split(".").length;

    const digits = sld.split("").filter((c) => /\d/.test(c)).length;
    const digitRatio =
      sld.length > 0 ? Math.round((digits / sld.length) * 100) / 100 : 0;

    const consonants = sld
      .toLowerCase()
      .split("")
      .filter((c) => CONSONANTS.has(c)).length;
    const consonantRatio =
      sld.length > 0
        ? Math.round((consonants / sld.length) * 100) / 100
        : 0;

    facts.push({ fact_type: "domain_string", fact_value: domain });
    facts.push({ fact_type: "sld", fact_value: sld });
    facts.push({ fact_type: "tld", fact_value: tld });
    facts.push({ fact_type: "entropy_score", fact_value: entropy });
    facts.push({ fact_type: "label_count", fact_value: labelCount });
    facts.push({ fact_type: "sld_length", fact_value: sld.length });
    facts.push({ fact_type: "digit_ratio", fact_value: digitRatio });
    facts.push({ fact_type: "consonant_ratio", fact_value: consonantRatio });

    return facts;
  }
}
