/**
 * IP-to-ASN lookup client.
 *
 * Uses ip-api.com free JSON endpoint.
 * Rate limits: 45 requests/minute on the free tier, no API key required.
 * Docs: https://ip-api.com/docs/api:json
 *
 * Fields requested: status, message, country, countryCode, isp, org, as, query
 */

const IPAPI_BASE = "http://ip-api.com/json";

export async function fetchIPASN(
  ip: string
): Promise<Record<string, unknown>> {
  const fields = "status,message,country,countryCode,isp,org,as,query";
  const url = `${IPAPI_BASE}/${encodeURIComponent(ip)}?fields=${fields}`;

  const response = await fetch(url, { cache: "no-store" });

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
