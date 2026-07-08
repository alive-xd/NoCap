/**
 * Investigation Orchestrator
 *
 * The central pipeline runner. Drives the full investigation pipeline:
 *   CREATED → FETCHING_ARTIFACTS → EXTRACTING_EVIDENCE →
 *   RUNNING_ANALYZERS → SCORING → COMPLETED / FAILED
 *
 * Design decisions:
 *   - Each pipeline stage updates the investigation status with a timestamp
 *   - Artifact caching: checks for a fresh artifact (< 24h) before fetching
 *   - Partial failure: if one source fails, continue with others; record failure
 *   - Only FAILED if ALL sources fail and there is nothing to score
 *   - Parsers and Analyzers are instantiated fresh per investigation (stateless)
 *   - All DB writes use the service role client (bypasses RLS for server-side ops)
 *
 * This file orchestrates the IOC investigation type. Separate orchestrator
 * functions below handle Phishing, Attack Surface, and CVE Watch types.
 */

import { createClient } from "@supabase/supabase-js";
import { createLocalClient, isLocalMode } from "@/lib/supabase/local";
import { generateCaseNumber } from "./caseNumber";
import { extractDomainFromIOC, isDomainLike } from "./iocDetector";
import { computeScore } from "./scoring";

// ── API Clients ───────────────────────────────────────────────────────────────
import { fetchVirusTotal } from "@/lib/apis/virustotal";
import { fetchAbuseIPDB } from "@/lib/apis/abuseipdb";
import { fetchWhois } from "@/lib/apis/whois";
import { fetchIPASN } from "@/lib/apis/ipasn";
import { fetchCrtSh } from "@/lib/apis/crtsh";
import { searchGitHubCode } from "@/lib/apis/github-search";
import { fetchNVDById } from "@/lib/apis/nvd";



// ── Parsers ───────────────────────────────────────────────────────────────────
import { VirusTotalParser } from "@/lib/parsers/VirusTotalParser";
import { AbuseIPDBParser } from "@/lib/parsers/AbuseIPDBParser";
import { WHOISParser } from "@/lib/parsers/WHOISParser";
import { DomainStringParser } from "@/lib/parsers/DomainStringParser";
import { ASNLookupParser } from "@/lib/parsers/ASNLookupParser";
import { SubdomainParser } from "@/lib/parsers/SubdomainParser";
import { HomographParser } from "@/lib/parsers/HomographParser";
import { EmailHeaderParser } from "@/lib/parsers/EmailHeaderParser";
import { CVEParser } from "@/lib/parsers/CVEParser";


// ── Analyzers ─────────────────────────────────────────────────────────────────
import { VirusTotalAnalyzer } from "@/lib/analyzers/VirusTotalAnalyzer";
import { AbuseIPDBAnalyzer } from "@/lib/analyzers/AbuseIPDBAnalyzer";
import { DomainAgeAnalyzer } from "@/lib/analyzers/DomainAgeAnalyzer";
import { EntropyAnalyzer } from "@/lib/analyzers/EntropyAnalyzer";
import { ASNReputationAnalyzer } from "@/lib/analyzers/ASNReputationAnalyzer";
import { HomographAnalyzer } from "@/lib/analyzers/HomographAnalyzer";
import { EmailAuthAnalyzer } from "@/lib/analyzers/EmailAuthAnalyzer";
import { FingerprintAnalyzer } from "@/lib/analyzers/FingerprintAnalyzer";
import { CVEPriorityAnalyzer } from "@/lib/analyzers/CVEPriorityAnalyzer";


import type {
  TargetType,
  InvestigationStatus,
  FailedSource,
  Evidence,
  Analyzer,
  AnalyzerInput,
  ProducedFinding,
} from "@/lib/pipeline/types";

// ── Supabase service client ───────────────────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getServiceClient(): any {
  if (isLocalMode) {
    return createLocalClient();
  }
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL!;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY!;
  return createClient(url, key, {
    auth: { persistSession: false },
  });
}

// ── Artifact freshness window ─────────────────────────────────────────────────
const PROVIDER_TTL_HOURS: Record<string, number> = {
  whois: 72,
  ipasn: 48,
  virustotal: 6,
  abuseipdb: 6,
  nvd: 24,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async function setStatus(
  db: ReturnType<typeof getServiceClient>,
  investigationId: string,
  status: InvestigationStatus
) {
  await db
    .from("investigations")
    .update({ status })
    .eq("id", investigationId);
}

/**
 * Checks for a cached artifact from the same source for the same target.
 * Returns the cached artifact ID if fresh, or null if we should fetch fresh.
 */
async function findCachedArtifact(
  db: ReturnType<typeof getServiceClient>,
  target: string,
  source: string
): Promise<{ id: string; raw_response: Record<string, unknown> } | null> {
  const ttlHours = PROVIDER_TTL_HOURS[source] ?? 24;
  const cutoff = new Date(
    Date.now() - ttlHours * 60 * 60 * 1000
  ).toISOString();

  // Find a recent investigation for the same target that has an artifact from this source
  const { data } = await db
    .from("artifacts")
    .select("id, raw_response, fetched_at, investigations!inner(target)")
    .eq("source", source)
    .gte("fetched_at", cutoff)
    .eq("investigations.target", target)
    .order("fetched_at", { ascending: false })
    .limit(1)
    .single();

  return data
    ? { id: data.id, raw_response: data.raw_response as Record<string, unknown> }
    : null;
}

/**
 * Stores a raw API response as an Artifact and returns the artifact ID.
 */
async function storeArtifact(
  db: ReturnType<typeof getServiceClient>,
  investigationId: string,
  source: string,
  rawResponse: Record<string, unknown>,
  isReused: boolean
): Promise<string> {
  const { data, error } = await db
    .from("artifacts")
    .insert({
      investigation_id: investigationId,
      source,
      raw_response: rawResponse,
      is_reused: isReused,
    })
    .select("id")
    .single();

  if (error || !data) {
    throw new Error(`Failed to store artifact for source ${source}: ${error?.message}`);
  }

  return data.id;
}

/**
 * Stores a batch of Evidence rows linked to an artifact.
 * Returns the inserted Evidence rows (with IDs).
 */
async function storeEvidence(
  db: ReturnType<typeof getServiceClient>,
  artifactId: string,
  facts: Array<{ fact_type: string; fact_value: unknown }>,
  parserName: string,
  parserVersion: string
): Promise<Evidence[]> {
  if (facts.length === 0) return [];

  const rows = facts.map((f) => ({
    artifact_id: artifactId,
    fact_type: f.fact_type,
    fact_value: f.fact_value,
    parser_name: parserName,
    parser_version: parserVersion,
  }));

  const { data, error } = await db.from("evidence").insert(rows).select();
  if (error || !data) {
    throw new Error(`Failed to store evidence: ${error?.message}`);
  }

  return data as Evidence[];
}

/**
 * Runs an analyzer against Evidence and persists Findings + junction rows.
 * Returns the count of Findings generated.
 */
async function runAnalyzerAndPersist(
  db: ReturnType<typeof getServiceClient>,
  analyzer: Analyzer,
  investigationId: string,
  evidenceRows: Evidence[],
  target: string,
  targetType: TargetType
): Promise<number> {
  const input: AnalyzerInput = {
    evidence: evidenceRows,
    investigationId,
    target,
    targetType,
  };

  let produced: ProducedFinding[] = [];
  try {
    produced = analyzer.analyze(input);
  } catch (err) {
    console.error(`Analyzer ${analyzer.config.name} threw:`, err);
    return 0;
  }

  if (produced.length === 0) return 0;

  for (const pf of produced) {
    const { data: findingData, error: findingError } = await db
      .from("findings")
      .insert({
        investigation_id: investigationId,
        claim: pf.claim,
        severity: pf.severity,
        confidence_score: pf.confidence_score,
        score_contribution: pf.score_contribution,
        status: "FLAGGED",
        generated_by: analyzer.config.name,
        analyzer_version: analyzer.config.version,
        reasoning: pf.reasoning,
        attack_techniques: pf.attack_techniques ?? [],
      })
      .select("id")
      .single();

    if (findingError || !findingData) continue;

    const findingId = findingData.id;

    // Insert junction rows for evidence backing this finding
    if (pf.evidence_ids.length > 0) {
      const junctions = pf.evidence_ids.map((eid) => ({
        finding_id: findingId,
        evidence_id: eid,
      }));
      await db.from("finding_evidence").insert(junctions);
    }
  }

  return produced.length;
}

// ─────────────────────────────────────────────────────────────────────────────
// IOC Investigation Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

export interface OrchestratorOptions {
  investigationId: string;
  userId: string;
  target: string;
  targetType: TargetType;
}




export async function runIOCInvestigation(
  options: OrchestratorOptions
): Promise<void> {
  const { investigationId, target, targetType } = options;
  const db = getServiceClient();
  const startTime = Date.now();

  const domain = isDomainLike(targetType)
    ? extractDomainFromIOC(target, targetType)
    : null;

  const isIP = targetType === "IP";

  const failedSources: FailedSource[] = [];
  let artifactsFetched = 0;
  let evidenceExtracted = 0;
  let findingsGenerated = 0;
  const allEvidence: Evidence[] = [];

  // ── FETCHING_ARTIFACTS ────────────────────────────────────────────────────

  await setStatus(db, investigationId, "FETCHING_ARTIFACTS");

  const SOURCES = [
    {
      name: "virustotal",
      fetch: async () => {
        if (targetType === "IP") return fetchVirusTotal("ip", target);
        if (targetType === "DOMAIN") return fetchVirusTotal("domain", target);
        if (targetType === "URL") return fetchVirusTotal("url", target);
        if (targetType === "HASH") return fetchVirusTotal("file", target);
        throw new Error("Unknown target type");
      },
      enabled: true,
    },
    {
      name: "abuseipdb",
      fetch: () => fetchAbuseIPDB(domain ?? target),
      enabled: isIP || !!domain,
    },
    {
      name: "whois",
      fetch: () => fetchWhois(domain ?? target),
      enabled: !!domain,
    },
    {
      name: "ipasn",
      fetch: () => fetchIPASN(domain ?? target),
      enabled: isIP || !!domain,
    },
    {
      name: "domainstring",
      // Synthetic artifact — no external API; the domain string itself is the "raw response"
      fetch: () => Promise.resolve({ domain: domain ?? target }),
      enabled: !!domain,
    },
  ];

  const artifactMap: Record<string, { artifactId: string; raw: Record<string, unknown> }> = {};

  const enabledSources = SOURCES.filter((s) => s.enabled);
  const fetchTasks = enabledSources.map(async (source) => {
    try {
      const cached =
        source.name !== "domainstring"
          ? await findCachedArtifact(db, target, source.name)
          : null;

      let raw: Record<string, unknown>;
      let isReused = false;

      if (cached) {
        raw = cached.raw_response;
        isReused = true;
      } else {
        raw = await source.fetch();
      }

      const artifactId = await storeArtifact(
        db,
        investigationId,
        source.name,
        raw,
        isReused
      );

      return { source: source.name, success: true, artifactId, raw, isReused };
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      return { source: source.name, success: false, reason };
    }
  });

  const fetchResults = await Promise.allSettled(fetchTasks);

  for (const res of fetchResults) {
    if (res.status === "fulfilled") {
      const val = res.value;
      if (val.success && val.artifactId && val.raw) {
        artifactMap[val.source] = { artifactId: val.artifactId, raw: val.raw };
        artifactsFetched++;
      } else if (!val.success && val.reason) {
        failedSources.push({ source: val.source, reason: val.reason });
        console.error(`[orchestrator] Source ${val.source} failed:`, val.reason);
      }
    } else {
      console.error("[orchestrator] Source task rejected:", res.reason);
    }
  }

  if (failedSources.length > 0) {
    await db
      .from("investigations")
      .update({ failed_sources: failedSources })
      .eq("id", investigationId);
  }

  // If EVERY source failed, mark as FAILED and exit
  if (Object.keys(artifactMap).length === 0) {
    await db.from("investigations").update({
      status: "FAILED",
      failed_sources: failedSources,
      completed_at: new Date().toISOString(),
    }).eq("id", investigationId);

    await db.from("investigation_metrics").upsert({
      investigation_id: investigationId,
      artifacts_fetched: 0,
      evidence_extracted: 0,
      findings_generated: 0,
      failed_sources_count: failedSources.length,
      execution_time_ms: Date.now() - startTime,
    });
    return;
  }

  // ── EXTRACTING_EVIDENCE ───────────────────────────────────────────────────

  await setStatus(db, investigationId, "EXTRACTING_EVIDENCE");

  const parserPairs: Array<{
    source: string;
    parser: { name: string; version: string; parse: (r: Record<string, unknown>) => Array<{ fact_type: string; fact_value: unknown }> };
  }> = [
    { source: "virustotal", parser: new VirusTotalParser() },
    { source: "abuseipdb", parser: new AbuseIPDBParser() },
    { source: "whois", parser: new WHOISParser() },
    { source: "domainstring", parser: new DomainStringParser() },
    { source: "ipasn", parser: new ASNLookupParser() },
  ];

  for (const { source, parser } of parserPairs) {
    const artifact = artifactMap[source];
    if (!artifact) continue;

    try {
      const facts = parser.parse(artifact.raw);
      const evidence = await storeEvidence(
        db,
        artifact.artifactId,
        facts,
        parser.name,
        parser.version
      );
      allEvidence.push(...evidence);
      evidenceExtracted += evidence.length;
    } catch (err) {
      console.error(`[orchestrator] Parser ${parser.name} threw:`, err);
    }
  }

  // ── RUNNING_ANALYZERS ─────────────────────────────────────────────────────

  await setStatus(db, investigationId, "RUNNING_ANALYZERS");

  const analyzers: Analyzer[] = [
    new VirusTotalAnalyzer(),
    new AbuseIPDBAnalyzer(),
    new DomainAgeAnalyzer(),
    new EntropyAnalyzer(),
    new ASNReputationAnalyzer(),
  ];

  for (const analyzer of analyzers) {
    const count = await runAnalyzerAndPersist(
      db,
      analyzer,
      investigationId,
      allEvidence,
      target,
      targetType
    );
    findingsGenerated += count;
  }

  // ── SCORING ───────────────────────────────────────────────────────────────

  await setStatus(db, investigationId, "SCORING");

  // Fetch the findings just created (with their score_contributions)
  const { data: findingRows } = await db
    .from("findings")
    .select("*")
    .eq("investigation_id", investigationId);

  const { data: profileRow } = await db
    .from("scoring_profiles")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(1)
    .single();

  const totalSources = SOURCES.filter((s) => s.enabled).length;
  const successfulSources = Object.keys(artifactMap).length;

  const scoreResult = computeScore(
    (findingRows ?? []) as Parameters<typeof computeScore>[0],
    profileRow as Parameters<typeof computeScore>[1],
    successfulSources,
    totalSources
  );

  

  // ── COMPLETED ─────────────────────────────────────────────────────────────

  await db.from("investigations").update({
        status: "COMPLETED",
    final_score: scoreResult.finalScore,
    scoring_profile_version: profileRow?.version ?? "1.0",
    failed_sources: failedSources,
    completed_at: new Date().toISOString(),
  }).eq("id", investigationId);

  await db.from("investigation_metrics").upsert({
    investigation_id: investigationId,
    artifacts_fetched: artifactsFetched,
    evidence_extracted: evidenceExtracted,
    findings_generated: findingsGenerated,
    failed_sources_count: failedSources.length,
    execution_time_ms: Date.now() - startTime,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Phishing Investigation Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

export interface PhishingOrchestratorOptions {
  investigationId: string;
  userId: string;
  target: string;    // URL or raw email headers
  targetType: TargetType;
  rawEmailHeaders?: string;
}

export async function runPhishingInvestigation(
  options: PhishingOrchestratorOptions
): Promise<void> {
  const { investigationId, target, targetType, rawEmailHeaders } = options;
  const db = getServiceClient();
  const startTime = Date.now();

  const failedSources: FailedSource[] = [];
  let artifactsFetched = 0;
  let evidenceExtracted = 0;
  let findingsGenerated = 0;
  const allEvidence: Evidence[] = [];

  await setStatus(db, investigationId, "FETCHING_ARTIFACTS");

  // Domain for homograph check
  const domain =
    targetType === "URL" || targetType === "DOMAIN"
      ? extractDomainFromIOC(target, targetType)
      : target;

  const artifacts: Record<string, { artifactId: string; raw: Record<string, unknown> }> = {};

  // Store homograph synthetic artifact
  try {
    const homographRaw = { domain };
    const aid = await storeArtifact(db, investigationId, "homograph", homographRaw, false);
    artifacts["homograph"] = { artifactId: aid, raw: homographRaw };
    artifactsFetched++;
  } catch (err) {
    failedSources.push({ source: "homograph", reason: String(err) });
  }

  // Store email headers artifact if provided
  if (rawEmailHeaders) {
    try {
      const headerRaw = { headers: rawEmailHeaders };
      const aid = await storeArtifact(db, investigationId, "email_headers", headerRaw, false);
      artifacts["email_headers"] = { artifactId: aid, raw: headerRaw };
      artifactsFetched++;
    } catch (err) {
      failedSources.push({ source: "email_headers", reason: String(err) });
    }
  }

  await setStatus(db, investigationId, "EXTRACTING_EVIDENCE");

  if (artifacts["homograph"]) {
    const parser = new HomographParser();
    const facts = parser.parse(artifacts["homograph"].raw);
    const evidence = await storeEvidence(db, artifacts["homograph"].artifactId, facts, parser.name, parser.version);
    allEvidence.push(...evidence);
    evidenceExtracted += evidence.length;
  }

  if (artifacts["email_headers"]) {
    const parser = new EmailHeaderParser();
    const facts = parser.parse(artifacts["email_headers"].raw);
    const evidence = await storeEvidence(db, artifacts["email_headers"].artifactId, facts, parser.name, parser.version);
    allEvidence.push(...evidence);
    evidenceExtracted += evidence.length;
  }

  await setStatus(db, investigationId, "RUNNING_ANALYZERS");

  const analyzers: Analyzer[] = [
    new HomographAnalyzer(),
    new EmailAuthAnalyzer(),
  ];

  for (const analyzer of analyzers) {
    const count = await runAnalyzerAndPersist(db, analyzer, investigationId, allEvidence, target, targetType);
    findingsGenerated += count;
  }

  await setStatus(db, investigationId, "SCORING");

  const { data: findingRows } = await db.from("findings").select("*").eq("investigation_id", investigationId);
  const { data: profileRow } = await db.from("scoring_profiles").select("*").order("created_at", { ascending: false }).limit(1).single();

  const scoreResult = computeScore(
    (findingRows ?? []) as Parameters<typeof computeScore>[0],
    profileRow as Parameters<typeof computeScore>[1],
    artifactsFetched,
    Object.keys(artifacts).length
  );

  await db.from("investigations").update({
    status: "COMPLETED",
    final_score: scoreResult.finalScore,
    scoring_profile_version: profileRow?.version ?? "1.0",
    failed_sources: failedSources,
    completed_at: new Date().toISOString(),
  }).eq("id", investigationId);

  await db.from("investigation_metrics").upsert({
    investigation_id: investigationId,
    artifacts_fetched: artifactsFetched,
    evidence_extracted: evidenceExtracted,
    findings_generated: findingsGenerated,
    failed_sources_count: failedSources.length,
    execution_time_ms: Date.now() - startTime,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Attack Surface Investigation Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

export async function runAttackSurfaceInvestigation(
  options: OrchestratorOptions
): Promise<void> {
  const { investigationId, target } = options;
  const db = getServiceClient();
  const startTime = Date.now();

  const failedSources: FailedSource[] = [];
  let artifactsFetched = 0;
  let evidenceExtracted = 0;
  let findingsGenerated = 0;
  const allEvidence: Evidence[] = [];

  await setStatus(db, investigationId, "FETCHING_ARTIFACTS");

  const artifacts: Record<string, { artifactId: string; raw: Record<string, unknown> }> = {};

  // crt.sh subdomain enumeration
  try {
    const crtResult = await fetchCrtSh(target);
    const raw = { entries: crtResult.raw, subdomains: crtResult.subdomains };
    const aid = await storeArtifact(db, investigationId, "crtsh", raw, false);
    artifacts["crtsh"] = { artifactId: aid, raw };
    artifactsFetched++;
  } catch (err) {
    failedSources.push({ source: "crtsh", reason: String(err) });
  }

  // GitHub exposure search (flagged for manual review, never auto-confirmed)
  try {
    const ghRaw = await searchGitHubCode(target);
    const aid = await storeArtifact(db, investigationId, "github_search", ghRaw, false);
    artifacts["github_search"] = { artifactId: aid, raw: ghRaw };
    artifactsFetched++;
  } catch (err) {
    failedSources.push({ source: "github_search", reason: String(err) });
  }

  await setStatus(db, investigationId, "EXTRACTING_EVIDENCE");

  if (artifacts["crtsh"]) {
    const parser = new SubdomainParser();
    const facts = parser.parse(artifacts["crtsh"].raw);
    const evidence = await storeEvidence(db, artifacts["crtsh"].artifactId, facts, parser.name, parser.version);
    allEvidence.push(...evidence);
    evidenceExtracted += evidence.length;
  }

  // GitHub search results: stored as evidence flagged for manual review
  if (artifacts["github_search"]) {
    const ghData = artifacts["github_search"].raw as { total_count?: number; items?: unknown[] };
    if ((ghData.total_count ?? 0) > 0) {
      const evidence = await storeEvidence(
        db,
        artifacts["github_search"].artifactId,
        [{
          fact_type: "potential_secret_exposure",
          fact_value: {
            total_results: ghData.total_count,
            items: (ghData.items ?? []).slice(0, 10).map((i: unknown) => {
              const item = i as { html_url?: string; repository?: { full_name?: string }; name?: string };
              return { url: item.html_url, repo: item.repository?.full_name, file: item.name };
            }),
            review_required: true,
            note: "Manual review required — never auto-confirmed as a Finding",
          },
        }],
        "GitHubExposureParser",
        "1.0"
      );
      allEvidence.push(...evidence);
      evidenceExtracted += evidence.length;
    }
  }

  await setStatus(db, investigationId, "RUNNING_ANALYZERS");

  // FingerprintAnalyzer needs HTTP response data — probe the target
  try {
    const httpResult = await probeHTTP(target);
    const httpAid = await storeArtifact(db, investigationId, "http_fingerprint", httpResult, false);
    const fingerEvidence = await storeEvidence(
      db,
      httpAid,
      Object.entries(httpResult).map(([fact_type, fact_value]) => ({ fact_type, fact_value })),
      "HTTPFingerprintParser",
      "1.0"
    );
    allEvidence.push(...fingerEvidence);
    evidenceExtracted += fingerEvidence.length;
    artifactsFetched++;
  } catch {
    failedSources.push({ source: "http_fingerprint", reason: "HTTP probe failed" });
  }

  const count = await runAnalyzerAndPersist(db, new FingerprintAnalyzer(), investigationId, allEvidence, target, "DOMAIN");
  findingsGenerated += count;

  await setStatus(db, investigationId, "SCORING");

  const { data: findingRows } = await db.from("findings").select("*").eq("investigation_id", investigationId);
  const { data: profileRow } = await db.from("scoring_profiles").select("*").order("created_at", { ascending: false }).limit(1).single();

  const scoreResult = computeScore(
    (findingRows ?? []) as Parameters<typeof computeScore>[0],
    profileRow as Parameters<typeof computeScore>[1],
    artifactsFetched,
    3
  );

  await db.from("investigations").update({
    status: "COMPLETED",
    final_score: scoreResult.finalScore,
    scoring_profile_version: profileRow?.version ?? "1.0",
    failed_sources: failedSources,
    completed_at: new Date().toISOString(),
  }).eq("id", investigationId);

  await db.from("investigation_metrics").upsert({
    investigation_id: investigationId,
    artifacts_fetched: artifactsFetched,
    evidence_extracted: evidenceExtracted,
    findings_generated: findingsGenerated,
    failed_sources_count: failedSources.length,
    execution_time_ms: Date.now() - startTime,
  });
}

/**
 * Probes a domain's HTTP responses to collect fingerprinting data.
 * Used by the Attack Surface investigation type.
 */
async function probeHTTP(domain: string): Promise<Record<string, unknown>> {
  const SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
  ];

  const PATHS_TO_PROBE = [
    "/wp-login.php",
    "/administrator/",
    "/.well-known/security.txt",
    "/robots.txt",
  ];

  try {
    const url = `https://${domain}`;
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
      headers: { "User-Agent": "Mozilla/5.0 (compatible; NoCap-Scanner/1.0)" },
    });

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const presentSecurityHeaders: string[] = [];
    const missingSecurityHeaders: string[] = [];
    for (const h of SECURITY_HEADERS) {
      if (headers[h]) presentSecurityHeaders.push(h);
      else missingSecurityHeaders.push(h);
    }

    const exposedPaths: string[] = [];
    for (const path of PATHS_TO_PROBE) {
      try {
        const r = await fetch(`https://${domain}${path}`, {
          method: "HEAD",
          signal: AbortSignal.timeout(3000),
        });
        if (r.status === 200) exposedPaths.push(path);
      } catch {
        // Path probe failed — skip
      }
    }

    return {
      server_header: headers["server"] ?? null,
      x_powered_by: headers["x-powered-by"] ?? null,
      x_generator: headers["x-generator"] ?? null,
      x_aspnet_version: headers["x-aspnet-version"] ?? null,
      detected_tech: [],
      present_security_headers: presentSecurityHeaders,
      missing_security_headers: missingSecurityHeaders,
      exposed_paths: exposedPaths,
      status_code: response.status,
    };
  } catch (err) {
    throw new Error(`HTTP probe failed for ${domain}: ${err}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Create investigation row (called by API route before running orchestrator)
// ─────────────────────────────────────────────────────────────────────────────

export async function createInvestigationRecord(
  userId: string,
  target: string,
  targetType: TargetType
): Promise<string> {
  const db = getServiceClient();
  const year = new Date().getFullYear();

  let retries = 5;
  while (retries > 0) {
    const { count } = await db
      .from("investigations")
      .select("*", { count: "exact", head: true });

    const sequenceNumber = (count ?? 0) + 1;
    const caseNumber = generateCaseNumber(year, sequenceNumber);

    const { data, error } = await db
      .from("investigations")
      .insert({
        user_id: userId,
        case_number: caseNumber,
        target,
        target_type: targetType,
        status: "CREATED",
      })
      .select("id")
      .single();

    if (error) {
      if (error.code === "23505" && retries > 1) {
        retries--;
        await new Promise((resolve) => setTimeout(resolve, Math.random() * 200 + 50));
        continue;
      }
      throw new Error(`Failed to create investigation: ${error.message}`);
    }

    if (!data) {
      throw new Error("Failed to create investigation record");
    }

    return data.id;
  }

  throw new Error("Failed to generate unique case number after multiple retries");
}

async function checkCisaKev(cveId: string): Promise<boolean> {
  try {
    const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return false;
    const data = await res.json() as { vulnerabilities?: Array<{ cveID: string }> };
    const list = data.vulnerabilities ?? [];
    return list.some((v) => v.cveID.toUpperCase() === cveId.toUpperCase());
  } catch {
    return false;
  }
}

async function checkExploitDb(cveId: string): Promise<boolean> {
  try {
    const cleanId = cveId.toUpperCase();
    const res = await fetch(`https://www.exploit-db.com/search?cve=${cleanId}`, {
      headers: { "User-Agent": "Mozilla/5.0" },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return false;
    const html = await res.text();
    return html.includes(cleanId);
  } catch {
    return false;
  }
}

export async function runCVEInvestigation(
  options: OrchestratorOptions
): Promise<void> {
  const { investigationId, target } = options;
  const db = getServiceClient();
  const startTime = Date.now();

  const failedSources: FailedSource[] = [];
  let artifactsFetched = 0;
  let evidenceExtracted = 0;
  let findingsGenerated = 0;
  const allEvidence: Evidence[] = [];

  await setStatus(db, investigationId, "FETCHING_ARTIFACTS");

  const artifactMap: Record<string, { artifactId: string; raw: Record<string, unknown> }> = {};

  try {
    // 1. Fetch NVD detail
    const nvdRaw = await fetchNVDById(target);
    const vulnList = (nvdRaw.vulnerabilities as Record<string, unknown>[]) ?? [];
    const cveObj = vulnList[0]?.cve ?? { id: target };

    // 2. Fetch Exploit status in parallel
    const [inCisaKev, hasKnownExploit] = await Promise.all([
      checkCisaKev(target),
      checkExploitDb(target),
    ]);

    const rawResponse = {
      cve: cveObj,
      in_cisa_kev: inCisaKev,
      has_known_exploit: hasKnownExploit,
    };

    const artifactId = await storeArtifact(
      db,
      investigationId,
      "nvd",
      rawResponse,
      false
    );

    artifactMap["nvd"] = { artifactId, raw: rawResponse };
    artifactsFetched++;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    failedSources.push({ source: "nvd", reason });
    console.error("[orchestrator] NVD fetch failed:", reason);

    await db
      .from("investigations")
      .update({ failed_sources: failedSources })
      .eq("id", investigationId);
  }

  // If NVD failed, mark as FAILED and exit
  if (Object.keys(artifactMap).length === 0) {
    await db.from("investigations").update({
      status: "FAILED",
      failed_sources: failedSources,
      completed_at: new Date().toISOString(),
    }).eq("id", investigationId);

    await db.from("investigation_metrics").upsert({
      investigation_id: investigationId,
      artifacts_fetched: 0,
      evidence_extracted: 0,
      findings_generated: 0,
      failed_sources_count: failedSources.length,
      execution_time_ms: Date.now() - startTime,
    });
    return;
  }

  // ── EXTRACTING_EVIDENCE ───────────────────────────────────────────────────
  await setStatus(db, investigationId, "EXTRACTING_EVIDENCE");

  const parser = new CVEParser();
  try {
    const facts = parser.parse(artifactMap["nvd"].raw);
    const evidence = await storeEvidence(
      db,
      artifactMap["nvd"].artifactId,
      facts,
      parser.name,
      parser.version
    );
    allEvidence.push(...evidence);
    evidenceExtracted += evidence.length;
  } catch (err) {
    console.error("[orchestrator] CVEParser failed:", err);
  }

  // ── RUNNING_ANALYZERS ─────────────────────────────────────────────────────
  await setStatus(db, investigationId, "RUNNING_ANALYZERS");

  const analyzer = new CVEPriorityAnalyzer();
  const count = await runAnalyzerAndPersist(
    db,
    analyzer,
    investigationId,
    allEvidence,
    target,
    "CVE"
  );
  findingsGenerated += count;

  // ── SCORING ───────────────────────────────────────────────────────────────
  await setStatus(db, investigationId, "SCORING");

  const { data: findingRows } = await db
    .from("findings")
    .select("*")
    .eq("investigation_id", investigationId);

  const { data: profileRow } = await db
    .from("scoring_profiles")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(1)
    .single();

  const scoreResult = computeScore(
    (findingRows ?? []) as Parameters<typeof computeScore>[0],
    profileRow as Parameters<typeof computeScore>[1],
    artifactsFetched,
    1
  );

  

  // ── COMPLETED ─────────────────────────────────────────────────────────────
  await db.from("investigations").update({
        status: "COMPLETED",
    final_score: scoreResult.finalScore,
    scoring_profile_version: profileRow?.version ?? "1.0",
    failed_sources: failedSources,
    completed_at: new Date().toISOString(),
  }).eq("id", investigationId);

  await db.from("investigation_metrics").upsert({
    investigation_id: investigationId,
    artifacts_fetched: artifactsFetched,
    evidence_extracted: evidenceExtracted,
    findings_generated: findingsGenerated,
    failed_sources_count: failedSources.length,
    execution_time_ms: Date.now() - startTime,
  });
}

