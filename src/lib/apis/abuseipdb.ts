/**
 * AbuseIPDB API client — raw data fetcher only.
 *
 * Rate limits (free tier): 1,000 checks/day.
 * Docs: https://docs.abuseipdb.com/#check-endpoint
 */

import { promises as dns } from "dns";
import { isIPv4, isIPv6 } from "net";

const ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2";
const TIMEOUT_MS = 8_000;

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

  let resolvedIp = ip;
  // Resolve domain to IP if it's not already an IP address
  if (!isIPv4(ip) && !isIPv6(ip)) {
    try {
      const addresses = await dns.resolve4(ip);
      if (addresses.length > 0) {
        resolvedIp = addresses[0];
      } else {
        throw new Error("No IP addresses found for domain");
      }
    } catch (err) {
      throw new Error(`DNS resolution failed for ${ip}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const params = new URLSearchParams({
    ipAddress: resolvedIp,
    maxAgeInDays: maxAgeInDays.toString(),
    verbose: "false",
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const response = await fetch(`${ABUSEIPDB_BASE}/check?${params}`, {
    headers: {
      Key: apiKey,
      Accept: "application/json",
    },
    cache: "no-store",
    signal: controller.signal,
  }).catch((err: unknown) => {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(`AbuseIPDB request timed out after ${TIMEOUT_MS / 1000}s`);
    }
    throw err;
  });
  clearTimeout(timer);

  if (!response.ok) {
    const errorText = await response.text().catch(() => response.statusText);
    throw new Error(`AbuseIPDB API error ${response.status}: ${errorText}`);
  }

  return response.json() as Promise<Record<string, unknown>>;
}
