/**
 * EmailHeaderParser v1.0
 *
 * Parses raw email header text and extracts authentication results
 * (SPF, DKIM, DMARC), routing hops, and mismatch flags.
 *
 * This parser does NOT call any external API — it operates purely on
 * the raw header text submitted by the user.
 *
 * Extracted fact types:
 *   - spf_result         : "pass" | "fail" | "softfail" | "neutral" | "none" | "permerror"
 *   - dkim_result        : "pass" | "fail" | "none"
 *   - dmarc_result       : "pass" | "fail" | "none"
 *   - from_domain        : domain in the From: header
 *   - reply_to_domain    : domain in the Reply-To: header (if different from From)
 *   - return_path_domain : domain in the Return-Path: header
 *   - mismatch_flags     : array of detected mismatches
 *   - received_hops      : array of parsed Received: hop objects
 *   - x_originating_ip   : X-Originating-IP header value if present
 *   - message_id_domain  : domain part of Message-ID
 */

import type { Parser, ParsedEvidence } from "@/lib/pipeline/types";

type AuthResult = "pass" | "fail" | "softfail" | "neutral" | "none" | "permerror" | "temperror" | "unknown";

interface ReceivedHop {
  from: string | null;
  by: string | null;
  date: string | null;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function extractDomain(email: string): string | null {
  // Extract domain from email address or bare domain
  const match = email.match(/@([a-zA-Z0-9.-]+)|^([a-zA-Z0-9.-]+\.[a-z]{2,})$/);
  return match ? (match[1] ?? match[2] ?? null) : null;
}

function parseAuthResult(text: string, protocol: "spf" | "dkim" | "dmarc"): AuthResult {
  const lc = text.toLowerCase();
  const results: AuthResult[] = [
    "pass", "fail", "softfail", "neutral", "none", "permerror", "temperror",
  ];

  // Search for pattern like "spf=pass" or "dkim=fail"
  const regex = new RegExp(`${protocol}=(\\S+)`, "i");
  const match = lc.match(regex);
  if (match) {
    const found = match[1].replace(/[^a-z]/g, "") as AuthResult;
    if (results.includes(found)) return found;
  }

  return "unknown";
}

function parseHeaders(rawHeaders: string): Record<string, string[]> {
  const headers: Record<string, string[]> = {};

  // Unfold headers (RFC 2822: continuation lines start with whitespace)
  const unfolded = rawHeaders.replace(/\r?\n([ \t])/g, " ");
  const lines = unfolded.split(/\r?\n/);

  for (const line of lines) {
    const colonIdx = line.indexOf(":");
    if (colonIdx < 0) continue;
    const name = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();
    if (!headers[name]) headers[name] = [];
    headers[name].push(value);
  }

  return headers;
}

function parseReceivedHop(received: string): ReceivedHop {
  const fromMatch = received.match(/from\s+(\S+)/i);
  const byMatch = received.match(/by\s+(\S+)/i);
  const dateMatch = received.match(/;\s*(.+)$/);

  return {
    from: fromMatch ? fromMatch[1] : null,
    by: byMatch ? byMatch[1] : null,
    date: dateMatch ? dateMatch[1].trim() : null,
  };
}

export class EmailHeaderParser implements Parser<Record<string, unknown>> {
  readonly name = "EmailHeaderParser";
  readonly version = "1.0";

  parse(raw: Record<string, unknown>): ParsedEvidence[] {
    const facts: ParsedEvidence[] = [];

    const rawHeaders = typeof raw["headers"] === "string" ? raw["headers"] : "";
    if (!rawHeaders) return facts;

    const headers = parseHeaders(rawHeaders);

    // ── Authentication Results ────────────────────────────────────────────────
    const authResults = (headers["authentication-results"] ?? []).join(" ");

    const spfResult = parseAuthResult(authResults, "spf");
    const dkimResult = parseAuthResult(authResults, "dkim");
    const dmarcResult = parseAuthResult(authResults, "dmarc");

    // Also check Received-SPF header as fallback
    const receivedSpf = (headers["received-spf"] ?? []).join(" ");
    const finalSpf =
      spfResult !== "unknown"
        ? spfResult
        : parseAuthResult(receivedSpf, "spf");

    facts.push({ fact_type: "spf_result", fact_value: finalSpf });
    facts.push({ fact_type: "dkim_result", fact_value: dkimResult });
    facts.push({ fact_type: "dmarc_result", fact_value: dmarcResult });

    // ── Domain Extraction ─────────────────────────────────────────────────────
    const fromHeader = (headers["from"] ?? [""])[0];
    const fromDomainMatch = fromHeader.match(/@([a-zA-Z0-9.-]+)/);
    const fromDomain = fromDomainMatch ? fromDomainMatch[1].toLowerCase() : null;
    if (fromDomain) {
      facts.push({ fact_type: "from_domain", fact_value: fromDomain });
    }

    const replyToHeader = (headers["reply-to"] ?? [""])[0];
    const replyToDomainMatch = replyToHeader.match(/@([a-zA-Z0-9.-]+)/);
    const replyToDomain = replyToDomainMatch
      ? replyToDomainMatch[1].toLowerCase()
      : null;
    if (replyToDomain) {
      facts.push({ fact_type: "reply_to_domain", fact_value: replyToDomain });
    }

    const returnPathHeader = (headers["return-path"] ?? [""])[0];
    const returnPathMatch = returnPathHeader.match(/@([a-zA-Z0-9.-]+)/);
    const returnPathDomain = returnPathMatch
      ? returnPathMatch[1].toLowerCase()
      : null;
    if (returnPathDomain) {
      facts.push({ fact_type: "return_path_domain", fact_value: returnPathDomain });
    }

    // ── Mismatch Flags ────────────────────────────────────────────────────────
    const mismatches: string[] = [];

    if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
      mismatches.push(
        `From domain (${fromDomain}) differs from Reply-To domain (${replyToDomain})`
      );
    }
    if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
      mismatches.push(
        `From domain (${fromDomain}) differs from Return-Path domain (${returnPathDomain})`
      );
    }
    if (finalSpf !== "pass" && finalSpf !== "unknown") {
      mismatches.push(`SPF ${finalSpf}`);
    }
    if (dkimResult === "fail") {
      mismatches.push("DKIM signature failed");
    }

    if (mismatches.length > 0) {
      facts.push({ fact_type: "mismatch_flags", fact_value: mismatches });
    }

    // ── Received Hops ─────────────────────────────────────────────────────────
    const receivedHops = (headers["received"] ?? []).map(parseReceivedHop);
    if (receivedHops.length > 0) {
      facts.push({ fact_type: "received_hops", fact_value: receivedHops });
      facts.push({ fact_type: "hop_count", fact_value: receivedHops.length });
    }

    // ── Additional signals ────────────────────────────────────────────────────
    const xOriginatingIP = (headers["x-originating-ip"] ?? [""])[0].trim();
    if (xOriginatingIP) {
      facts.push({ fact_type: "x_originating_ip", fact_value: xOriginatingIP });
    }

    const messageId = (headers["message-id"] ?? [""])[0];
    const msgIdDomainMatch = messageId.match(/@([a-zA-Z0-9.-]+)/);
    if (msgIdDomainMatch) {
      facts.push({
        fact_type: "message_id_domain",
        fact_value: msgIdDomainMatch[1].toLowerCase(),
      });
    }

    return facts;
  }
}
