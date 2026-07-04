/**
 * NVD (National Vulnerability Database) CVE API client.
 *
 * Uses NVD API 2.0: https://nvd.nist.gov/developers/vulnerabilities
 * Free, API key optional (higher rate limit with key: 50 req/30s vs 5 req/30s).
 * Set NVD_API_KEY in .env for the higher rate limit.
 */

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

export interface NVDCve {
  id: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  descriptions: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV31?: Array<{
      cvssData: {
        baseScore: number;
        baseSeverity: string;
        vectorString: string;
      };
    }>;
    cvssMetricV2?: Array<{
      cvssData: {
        baseScore: number;
      };
    }>;
  };
  references?: Array<{ url: string; source: string; tags?: string[] }>;
}

export interface NVDResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities: Array<{ cve: NVDCve }>;
}

/**
 * Searches for CVEs by keyword (e.g. "Microsoft Exchange").
 * Returns raw NVD API response.
 */
export async function fetchNVDByKeyword(
  keyword: string,
  resultsPerPage = 20
): Promise<Record<string, unknown>> {
  const params = new URLSearchParams({
    keywordSearch: keyword,
    resultsPerPage: resultsPerPage.toString(),
    pubStartDate: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000)
      .toISOString()
      .replace("Z", "+00:00"),
    pubEndDate: new Date().toISOString().replace("Z", "+00:00"),
  });

  const headers: HeadersInit = {
    Accept: "application/json",
  };

  const apiKey = process.env.NVD_API_KEY;
  if (apiKey) {
    headers["apiKey"] = apiKey;
  }

  const response = await fetch(`${NVD_BASE}?${params}`, {
    headers,
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`NVD API error ${response.status} for keyword "${keyword}"`);
  }

  return response.json() as Promise<Record<string, unknown>>;
}

/**
 * Fetches a specific CVE by ID.
 */
export async function fetchNVDById(
  cveId: string
): Promise<Record<string, unknown>> {
  const headers: HeadersInit = { Accept: "application/json" };
  const apiKey = process.env.NVD_API_KEY;
  if (apiKey) headers["apiKey"] = apiKey;

  const response = await fetch(`${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`, {
    headers,
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`NVD API error ${response.status} for CVE ${cveId}`);
  }

  return response.json() as Promise<Record<string, unknown>>;
}
