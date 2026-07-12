/**
 * WHOIS client — uses the whois-json npm package.
 *
 * whois-json: https://www.npmjs.com/package/whois-json
 * No API key required. Queries WHOIS servers directly.
 *
 * This module returns the raw whois-json result as a plain object
 * so it can be stored as an immutable Artifact. All interpretation
 * happens in WHOISParser.
 */

// Dynamic import because whois-json is a CommonJS module
const TIMEOUT_MS = 8_000;

export async function fetchWhois(
  domain: string
): Promise<Record<string, unknown>> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const whois = require("whois-json") as (
    target: string,
    opts?: { follow: number }
  ) => Promise<Record<string, unknown>>;

  const timeout = new Promise<never>((_, reject) =>
    setTimeout(
      () => reject(new Error(`WHOIS request timed out after ${TIMEOUT_MS / 1000}s for ${domain}`)),
      TIMEOUT_MS
    )
  );

  try {
    const result = await Promise.race([whois(domain, { follow: 3 }), timeout]);
    return result;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`WHOIS lookup failed for ${domain}: ${message}`);
  }
}

