/**
 * VirusTotal API client — raw data fetcher only.
 *
 * This module's ONLY job is to call the VirusTotal API and return the raw
 * JSON response. Zero business logic, zero parsing, zero judgment.
 * Business logic belongs in VirusTotalParser and VirusTotalAnalyzer.
 *
 * Rate limits (free tier): 4 requests/minute, 500/day.
 * Artifact caching in the orchestrator handles repeat requests.
 */

const VT_BASE = "https://www.virustotal.com/api/v3";

export type VTResourceType = "ip" | "domain" | "url" | "file";

/**
 * Determines the VT endpoint path based on resource type and value.
 */
function vtPath(type: VTResourceType, value: string): string {
  switch (type) {
    case "ip":
      return `/ip_addresses/${encodeURIComponent(value)}`;
    case "domain":
      return `/domains/${encodeURIComponent(value)}`;
    case "url": {
      // VT URL lookups require a base64-encoded URL identifier
      const id = Buffer.from(value).toString("base64url");
      return `/urls/${id}`;
    }
    case "file":
      return `/files/${encodeURIComponent(value)}`;
  }
}

/**
 * Fetches a raw VirusTotal report. Returns the parsed JSON.
 * Throws on HTTP error or missing API key.
 */
export async function fetchVirusTotal(
  type: VTResourceType,
  value: string
): Promise<Record<string, unknown>> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    throw new Error("VIRUSTOTAL_API_KEY is not configured");
  }

  const url = `${VT_BASE}${vtPath(type, value)}`;

  const response = await fetch(url, {
    headers: {
      "x-apikey": apiKey,
      Accept: "application/json",
    },
    // Next.js: no cache — we manage freshness via Artifact caching
    cache: "no-store",
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => response.statusText);
    throw new Error(
      `VirusTotal API error ${response.status}: ${errorText}`
    );
  }

  return response.json() as Promise<Record<string, unknown>>;
}
