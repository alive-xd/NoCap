/**
 * WHOISParser v1.0
 *
 * Transforms raw WHOIS data into atomic Evidence facts.
 * No judgment — DomainAgeAnalyzer applies judgment to registration_date.
 *
 * WHOIS data varies enormously by registrar. This parser handles the most
 * common field names across major registrars (GoDaddy, Namecheap,
 * Cloudflare, Google Domains, etc.) with fallback chains.
 *
 * Extracted fact types:
 *   - registration_date    : ISO date string of domain creation
 *   - expiry_date          : ISO date string of domain expiry
 *   - registrar            : registrar name
 *   - registrant_country   : registrant country (often redacted by privacy)
 *   - name_servers         : array of authoritative nameserver hostnames
 *   - dnssec               : DNSSEC status string
 *   - updated_date         : last updated date
 */

import type { Parser, ParsedEvidence } from "@/lib/pipeline/types";

// Known field name variants across major registrars
const CREATION_FIELDS = [
  "creationDate",
  "creation_date",
  "created",
  "domainCreated",
  "registrationDate",
  "registered",
  "registeredOn",
];

const EXPIRY_FIELDS = [
  "expirationDate",
  "expiry_date",
  "expires",
  "registryExpiryDate",
  "registrarRegistrationExpirationDate",
  "expiredDate",
  "paid-till",
];

const UPDATED_FIELDS = [
  "updatedDate",
  "updated_date",
  "lastModified",
  "lastUpdated",
  "changed",
];

const REGISTRAR_FIELDS = [
  "registrar",
  "sponsoringRegistrar",
  "registrar-name",
  "registrarName",
];

const COUNTRY_FIELDS = [
  "registrantCountry",
  "countryCode",
  "country",
  "registrant_country",
];

const NS_FIELDS = [
  "nameServer",
  "nameServers",
  "nServer",
  "nameserver",
  "ns",
];

function findField(
  obj: Record<string, unknown>,
  fields: string[]
): string | null {
  for (const field of fields) {
    const val = obj[field];
    if (val) {
      if (Array.isArray(val)) return val[0] ? String(val[0]) : null;
      return String(val);
    }
  }
  return null;
}

function findArrayField(
  obj: Record<string, unknown>,
  fields: string[]
): string[] {
  for (const field of fields) {
    const val = obj[field];
    if (val) {
      if (Array.isArray(val)) return val.map(String);
      if (typeof val === "string" && val.trim().length > 0) {
        return val
          .split(/\s+/)
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean);
      }
    }
  }
  return [];
}

function parseDate(raw: string | null): string | null {
  if (!raw) return null;
  const cleaned = raw.replace(/T\d{2}:\d{2}:\d{2}.*$/, "").trim();
  const date = new Date(cleaned);
  if (isNaN(date.getTime())) return null;
  return date.toISOString();
}

export class WHOISParser implements Parser<Record<string, unknown>> {
  readonly name = "WHOISParser";
  readonly version = "1.0";

  parse(raw: Record<string, unknown>): ParsedEvidence[] {
    const facts: ParsedEvidence[] = [];

    const createdRaw = findField(raw, CREATION_FIELDS);
    const created = parseDate(createdRaw);
    if (created) {
      facts.push({ fact_type: "registration_date", fact_value: created });
    }

    const expiryRaw = findField(raw, EXPIRY_FIELDS);
    const expiry = parseDate(expiryRaw);
    if (expiry) {
      facts.push({ fact_type: "expiry_date", fact_value: expiry });
    }

    const updatedRaw = findField(raw, UPDATED_FIELDS);
    const updated = parseDate(updatedRaw);
    if (updated) {
      facts.push({ fact_type: "updated_date", fact_value: updated });
    }

    const registrar = findField(raw, REGISTRAR_FIELDS);
    if (registrar) {
      facts.push({ fact_type: "registrar", fact_value: registrar });
    }

    const country = findField(raw, COUNTRY_FIELDS);
    if (country) {
      facts.push({ fact_type: "registrant_country", fact_value: country });
    }

    const nameServers = findArrayField(raw, NS_FIELDS);
    if (nameServers.length > 0) {
      facts.push({ fact_type: "name_servers", fact_value: nameServers });
    }

    const dnssec = raw["dnssec"] ?? raw["DNSSEC"];
    if (dnssec) {
      facts.push({ fact_type: "dnssec", fact_value: String(dnssec) });
    }

    return facts;
  }
}
