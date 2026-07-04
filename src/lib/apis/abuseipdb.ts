/**
 * AbuseIPDB API client — raw data fetcher only.
 *
 * Rate limits (free tier): 1,000 checks/day.
 * Docs: https://docs.abuseipdb.com/#check-endpoint
 */

const ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2";

/**
 * Fetches a raw AbuseIPDB check report for an IP address.
 * maxAgeInDays: how many days of reports to include (default: 90).
 */
export async function fetchAbuseIPDB(
  ip: string,
  maxAgeInDays = 90
): Promise<Record<string, unknown>> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    throw new Error("ABUSEIPDB_API_KEY is not configured");
  }

  const params = new URLSearchParams({
    ipAddress: ip,
    maxAgeInDays: maxAgeInDays.toString(),
    verbose: "false",
  });

  const response = await fetch(`${ABUSEIPDB_BASE}/check?${params}`, {
    headers: {
      Key: apiKey,
      Accept: "application/json",
    },
    cache: "no-store",
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => response.statusText);
    throw new Error(`AbuseIPDB API error ${response.status}: ${errorText}`);
  }

  return response.json() as Promise<Record<string, unknown>>;
}
