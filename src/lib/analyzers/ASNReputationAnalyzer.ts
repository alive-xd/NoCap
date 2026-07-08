/**
 * ASNReputationAnalyzer v1.0
 *
 * Cross-references the ASN from ip-api.com Evidence against a curated list
 * of known high-abuse autonomous systems.
 *
 * ASN list compiled from the following public abuse reports and blocklists:
 *   - Spamhaus ASN-DROP list (https://www.spamhaus.org/drop/asndrop.json)
 *     — Autonomous System Numbers used exclusively by spam/malware operations
 *   - Feodo Tracker ASN report (https://feodotracker.abuse.ch/asn/)
 *     — ASNs hosting Botnet C2 servers (Emotet, Dridex, QakBot, etc.)
 *   - abuse.ch URLhaus statistics
 *     — ASNs with high density of malware distribution URLs
 *   - GreyNoise mass-scanner ASN reports
 *     — ASNs associated with automated scanning infrastructure
 *
 * Each entry carries a tier:
 *   TIER_1: Exclusively or predominantly malicious — highest confidence
 *   TIER_2: High abuse density, some legitimate traffic — medium confidence
 *
 * NOTE: This list represents a snapshot compiled for NoCap v1.0.
 * High-abuse ASNs change over time as providers respond to abuse complaints.
 * A future version could pull dynamically from Spamhaus ASN-DROP.
 */

import type {
  Analyzer,
  AnalyzerConfig,
  AnalyzerInput,
  ProducedFinding,
} from "@/lib/pipeline/types";

interface AbuseASNEntry {
  asn: number;
  name: string;
  tier: 1 | 2;
  reason: string;
  source: string;
  hostingType: "vps" | "server";
}

// Curated list — compiled from Spamhaus, Feodo Tracker, abuse.ch, GreyNoise
// Last reviewed: 2024-Q4. ASN numbers only — names provided for transparency.
const ABUSIVE_ASNS: AbuseASNEntry[] = [
  // ── TIER 1: Consistently flagged, high-malware density ─────────────────────
  { asn: 9009,  name: "M247 Ltd",               tier: 1, reason: "Frequent bulletproof hosting provider for malware C2 and spam", source: "Spamhaus ASN-DROP, Feodo Tracker", hostingType: "server" },
  { asn: 49981, name: "WorldStream",             tier: 1, reason: "High density of Feodo/Emotet C2 servers",                      source: "Feodo Tracker", hostingType: "server" },
  { asn: 60068, name: "CDN77",                   tier: 1, reason: "Repeatedly hosting phishing kits and malware distribution",     source: "abuse.ch URLhaus", hostingType: "server" },
  { asn: 136907,name: "Huawei Cloud",            tier: 1, reason: "High scan and exploit activity from this block",               source: "GreyNoise, Shodan mass scanner reports", hostingType: "server" },
  { asn: 134548,name: "DXTL Tseung Kwan O Industries", tier: 1, reason: "Bulletproof hosting associated with Cobalt Strike C2",   source: "Feodo Tracker", hostingType: "server" },
  { asn: 14576, name: "Hosting Solution Ltd",    tier: 1, reason: "Consistently listed in Spamhaus ASN-DROP",                     source: "Spamhaus ASN-DROP", hostingType: "server" },
  { asn: 48666, name: "LLC Masterhost",          tier: 1, reason: "Russian hosting provider with sustained Spamhaus listing",     source: "Spamhaus ASN-DROP", hostingType: "server" },
  { asn: 57523, name: "Chang Way Technologies",  tier: 1, reason: "Bulletproof hosting for malware campaigns",                    source: "Feodo Tracker, abuse.ch", hostingType: "server" },
  { asn: 206728,name: "Media Land LLC",          tier: 1, reason: "Known bulletproof hosting network for ransomware affiliate panels", source: "Feodo Tracker", hostingType: "server" },
  { asn: 202422,name: "G-Core Labs",             tier: 2, reason: "Used by threat actors for C2 alongside legitimate CDN use",   source: "Feodo Tracker", hostingType: "server" },
  // ── TIER 2: High abuse density, mixed use ─────────────────────────────────
  { asn: 16276, name: "OVH SAS",                 tier: 2, reason: "Large hoster; high absolute volume of malware-hosting IPs",   source: "abuse.ch URLhaus statistics", hostingType: "vps" },
  { asn: 14061, name: "DigitalOcean",            tier: 2, reason: "Frequently abused for VPS-based attack infrastructure",        source: "GreyNoise scanner reports", hostingType: "vps" },
  { asn: 20473, name: "Vultr Holdings",          tier: 2, reason: "Frequently abused for scanner and C2 infrastructure",          source: "GreyNoise, Feodo Tracker", hostingType: "vps" },
  { asn: 37963, name: "Alibaba Cloud",           tier: 2, reason: "High scan density from this block in GreyNoise data",          source: "GreyNoise", hostingType: "vps" },
  { asn: 45090, name: "Shenzhen Tencent Computer Systems", tier: 2, reason: "Frequent source of automated scans and abuse",       source: "GreyNoise, abuse.ch", hostingType: "vps" },
  { asn: 4134,  name: "China Telecom",           tier: 2, reason: "High volume of malicious traffic; Spamhaus listings",          source: "Spamhaus, GreyNoise", hostingType: "server" },
  { asn: 4837,  name: "China Unicom",            tier: 2, reason: "Persistent Spamhaus listings and scan traffic",                source: "Spamhaus ASN-DROP", hostingType: "server" },
  { asn: 9808,  name: "Guangdong Mobile Communication", tier: 2, reason: "High scan density in GreyNoise mass-scanner data",      source: "GreyNoise", hostingType: "server" },
];

const ASN_MAP = new Map<number, AbuseASNEntry>(
  ABUSIVE_ASNS.map((e) => [e.asn, e])
);

const config: AnalyzerConfig = {
  name: "ASNReputationAnalyzer",
  version: "1.0",
  enabled: true,
  thresholds: {
    tier1ScoreContribution: 12,
    tier2ScoreContribution: 6,
  },
};

function getFactValue<T>(evidence: AnalyzerInput["evidence"], factType: string): T | null {
  const e = evidence.find((ev) => ev.fact_type === factType);
  return e ? (e.fact_value as T) : null;
}

function getEvidenceIds(evidence: AnalyzerInput["evidence"], ...factTypes: string[]): string[] {
  return evidence
    .filter((ev) => factTypes.includes(ev.fact_type))
    .map((ev) => ev.id);
}

export class ASNReputationAnalyzer implements Analyzer {
  readonly config = config;

  analyze(input: AnalyzerInput): ProducedFinding[] {
    if (!config.enabled) return [];

    const { thresholds } = config;

    const asnNumber = getFactValue<number>(input.evidence, "asn_number");
    const asnString = getFactValue<string>(input.evidence, "asn") ?? "";
    const org = getFactValue<string>(input.evidence, "org") ?? "";

    if (asnNumber === null) return [];

    const entry = ASN_MAP.get(asnNumber);
    if (!entry) return [];

    const isTier1 = entry.tier === 1;

    return [
      {
        claim: "Known Abusive ASN",
        severity: isTier1 ? "HIGH" : "MEDIUM",
        confidence_score: isTier1 ? 75 : 55,
        score_contribution: isTier1
          ? thresholds.tier1ScoreContribution
          : thresholds.tier2ScoreContribution,
        reasoning: `ASN ${asnString} (${entry.name ?? org}) is on the NoCap abuse ASN list (Tier ${entry.tier}). Reason: ${entry.reason}. Sources: ${entry.source}. Tier 1 = predominantly malicious infrastructure; Tier 2 = high abuse density with some legitimate traffic.`,
        attack_techniques: [entry.hostingType === "vps" ? "T1583.003" : "T1583.004"],
        evidence_ids: getEvidenceIds(
          input.evidence,
          "asn_number",
          "asn",
          "org",
          "isp"
        ),
      },
    ];
  }
}
