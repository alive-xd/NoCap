/**
 * IOC Type Detector
 *
 * Auto-detects the type of an IOC (Indicator of Compromise) from its string form.
 * Returns a TargetType: "IP" | "DOMAIN" | "URL" | "HASH"
 *
 * Detection order matters — checked in specificity order:
 *   1. URL (contains scheme like http:// or https://)
 *   2. IP address (IPv4 or IPv6)
 *   3. Hash (MD5 / SHA-1 / SHA-256 by length and hex chars)
 *   4. Domain (catch-all for valid FQDN patterns)
 */

import type { TargetType } from "@/lib/pipeline/types";

// IPv4 with optional CIDR
const IPV4_REGEX =
  /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

// Simplified IPv6 check
const IPV6_REGEX =
  /^([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}$/;

// URL: has a scheme
const URL_REGEX = /^https?:\/\/.+/i;

// Domain: valid FQDN (allows subdomains, hyphens, international-ish)
const DOMAIN_REGEX =
  /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

// Hex hash by length: MD5=32, SHA1=40, SHA256=64
const HASH_REGEX = /^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/;

export function detectIOCType(raw: string): TargetType {
  const trimmed = raw.trim();

  if (/^CVE-\d{4}-\d{4,8}$/i.test(trimmed)) return "CVE";

  if (URL_REGEX.test(trimmed)) return "URL";

  if (IPV4_REGEX.test(trimmed)) {
    // Validate octet ranges
    const octets = trimmed.split("/")[0].split(".").map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) return "IP";
  }

  if (IPV6_REGEX.test(trimmed)) return "IP";

  if (HASH_REGEX.test(trimmed)) return "HASH";

  if (DOMAIN_REGEX.test(trimmed)) return "DOMAIN";

  // Default to DOMAIN for anything else that could be a target
  return "DOMAIN";
}

/**
 * Returns whether a given IOC type requires domain-specific parsers.
 */
export function isDomainLike(type: TargetType): boolean {
  return type === "DOMAIN" || type === "URL";
}

/**
 * Extracts the domain from a URL for WHOIS/entropy lookups.
 */
export function extractDomainFromIOC(ioc: string, type: TargetType): string {
  if (type === "URL") {
    try {
      return new URL(ioc).hostname;
    } catch {
      // Fallback: strip scheme manually
      return ioc.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    }
  }
  return ioc;
}
