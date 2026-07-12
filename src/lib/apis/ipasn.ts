/**
 * IP-to-ASN lookup client.
 *
 * Uses ip-api.com free JSON endpoint.
 * Rate limits: 45 requests/minute on the free tier, no API key required.
 * Docs: https://ip-api.com/docs/api:json
 *
 * Fields requested: status, message, country, countryCode, isp, org, as, query
 */

import { promises as dns } from "dns";
import { isIPv4, isIPv6 } from "net";

const IPAPI_BASE = "http://ip-api.com/json";
const TIMEOUT_MS = 8_000;

export async function fetchIPASN(
  target: string
): Promise<Record<string, unknown>> {
  let ip = target;

  // Resolve domain to IP if it's not already an IP address
  if (!isIPv4(target) && !isIPv6(target)) {
    try {
      const addresses = await dns.resolve4(target);
      if (addresses.length > 0) {
        ip = addresses[0];
      } else {
        throw new Error("No IP addresses found for domain");
      }
    } catch (err) {
      throw new Error(`DNS resolution failed for ${target}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const fields = "status,message,country,countryCode,isp,org,as,query";
  const url = `${IPAPI_BASE}/${encodeURIComponent(ip)}?fields=${fields}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const response = await fetch(url, {
    cache: "no-store",
    signal: controller.signal,
  }).catch((err: unknown) => {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(`ip-api.com request timed out after ${TIMEOUT_MS / 1000}s`);
    }
    throw err;
  });
  clearTimeout(timer);

  if (!response.ok) {
    throw new Error(`ip-api.com error ${response.status} for ${ip}`);
  }

  const data = (await response.json()) as Record<string, unknown>;

  if (data.status === "fail") {
    throw new Error(
      `ip-api.com lookup failed for ${ip}: ${data.message ?? "unknown error"}`
    );
  }

  return data;
}
