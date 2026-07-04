/**
 * crt.sh Certificate Transparency log client.
 *
 * crt.sh is a public CT log search engine by Comodo/Sectigo.
 * No API key required. Returns certificates containing a given domain.
 * Docs: https://crt.sh
 *
 * Used by SubdomainParser to enumerate subdomains from CT logs.
 */

const CRTSH_BASE = "https://crt.sh";

export interface CrtShEntry {
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;      // may contain newline-separated SANs
  id: number;
  entry_timestamp: string;
  not_before: string;
  not_after: string;
}

/**
 * Fetches certificate transparency entries for a domain.
 * Returns deduplicated subdomain names extracted from CN/SAN fields.
 */
export async function fetchCrtSh(
  domain: string
): Promise<{ raw: CrtShEntry[]; subdomains: string[] }> {
  const params = new URLSearchParams({
    q: `%.${domain}`,
    output: "json",
    deduplicate: "Y",
  });

  const response = await fetch(`${CRTSH_BASE}/?${params}`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`crt.sh error ${response.status} for ${domain}`);
  }

  const raw = (await response.json()) as CrtShEntry[];

  // Extract all unique hostnames from name_value fields
  const hostnameSet = new Set<string>();
  for (const entry of raw) {
    const names = entry.name_value
      .split(/\n/)
      .map((n) => n.trim().toLowerCase())
      .filter((n) => n && !n.startsWith("*"));
    names.forEach((n) => hostnameSet.add(n));
  }

  return {
    raw,
    subdomains: Array.from(hostnameSet).sort(),
  };
}
