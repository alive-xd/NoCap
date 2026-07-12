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
const TIMEOUT_MS = 8_000;

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
  
  if (!apiKey || apiKey.includes("placeholder") || apiKey.includes("your-")) {
    throw new Error("VIRUSTOTAL_API_KEY is not configured or is a placeholder");
  }

  const url = `${VT_BASE}${vtPath(type, value)}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const response = await fetch(url, {
    headers: {
      "x-apikey": apiKey,
      Accept: "application/json",
    },
    // Next.js: no cache — we manage freshness via Artifact caching
    cache: "no-store",
    signal: controller.signal,
  }).catch((err: unknown) => {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(`VirusTotal request timed out after ${TIMEOUT_MS / 1000}s`);
    }
    throw err;
  });
  clearTimeout(timer);

  if (!response.ok) {
    if (response.status === 404 && type === "url") {
      return await submitAndPollVTUrl(value, apiKey);
    }
    const errorText = await response.text().catch(() => response.statusText);
    throw new Error(
      `VirusTotal API error ${response.status}: ${errorText}`
    );
  }

  return response.json() as Promise<Record<string, unknown>>;
}

async function submitAndPollVTUrl(
  value: string,
  apiKey: string
): Promise<Record<string, unknown>> {
  const submitBody = new URLSearchParams({ url: value });
  const submitController = new AbortController();
  const submitTimer = setTimeout(() => submitController.abort(), TIMEOUT_MS);
  const submitRes = await fetch(`${VT_BASE}/urls`, {
    method: "POST",
    headers: {
      "x-apikey": apiKey,
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: submitBody,
    cache: "no-store",
    signal: submitController.signal,
  }).catch((err: unknown) => {
    clearTimeout(submitTimer);
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error(`VirusTotal URL submission timed out after ${TIMEOUT_MS / 1000}s`);
    }
    throw err;
  });
  clearTimeout(submitTimer);

  if (!submitRes.ok) {
    const errorText = await submitRes.text().catch(() => submitRes.statusText);
    throw new Error(`VirusTotal URL submission failed (${submitRes.status}): ${errorText}`);
  }

  const submitData = (await submitRes.json()) as { data?: { id?: string } };
  const analysisId = submitData.data?.id;
  if (!analysisId) {
    throw new Error("VirusTotal submission returned no analysis ID");
  }

  const maxAttempts = 12; // ~45s total with backoff
  let delay = 2000;

  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((resolve) => setTimeout(resolve, delay));
    
    const pollController = new AbortController();
    const pollTimer = setTimeout(() => pollController.abort(), TIMEOUT_MS);
    const analysisRes = await fetch(`${VT_BASE}/analyses/${analysisId}`, {
      headers: { "x-apikey": apiKey, Accept: "application/json" },
      cache: "no-store",
      signal: pollController.signal,
    }).catch((err: unknown) => {
      clearTimeout(pollTimer);
      if (err instanceof Error && err.name === "AbortError") {
        throw new Error(`VirusTotal analysis poll timed out after ${TIMEOUT_MS / 1000}s`);
      }
      throw err;
    });
    clearTimeout(pollTimer);

    if (!analysisRes.ok) {
       const errorText = await analysisRes.text().catch(() => analysisRes.statusText);
       throw new Error(`VirusTotal analysis poll failed (${analysisRes.status}): ${errorText}`);
    }

    const analysisData = (await analysisRes.json()) as { data?: { attributes?: { status?: string } } };
    const status = analysisData.data?.attributes?.status;

    if (status === "completed") {
      // Return the full URL report now that scanning is finished
      return await fetchVirusTotal("url", value);
    }

    delay = Math.min(delay * 1.5, 5000);
  }

  throw new Error("VirusTotal URL analysis timed out after waiting");
}
