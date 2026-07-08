/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runIOCInvestigation } from "../orchestrator";
import { fetchVirusTotal } from "@/lib/apis/virustotal";
import { fetchAbuseIPDB } from "@/lib/apis/abuseipdb";
import { fetchWhois } from "@/lib/apis/whois";
import { fetchIPASN } from "@/lib/apis/ipasn";
import { computeScore } from "../scoring";

// Mock the APIs
vi.mock("@/lib/apis/virustotal", () => ({ fetchVirusTotal: vi.fn() }));
vi.mock("@/lib/apis/abuseipdb", () => ({ fetchAbuseIPDB: vi.fn() }));
vi.mock("@/lib/apis/whois", () => ({ fetchWhois: vi.fn() }));
vi.mock("@/lib/apis/ipasn", () => ({ fetchIPASN: vi.fn() }));
vi.mock("@/lib/apis/crtsh", () => ({ fetchCrtSh: vi.fn() }));
vi.mock("@/lib/apis/github-search", () => ({ searchGitHubCode: vi.fn() }));
vi.mock("@/lib/apis/nvd", () => ({ fetchNVDById: vi.fn() }));

const globalUpdates: any[] = [];
const globalInserts: any[] = [];
const tableMocks = { findingsData: [] as any[] };

const createFakeQueryBuilder = (table: string) => {
  const builder: any = {};
  builder.select = vi.fn().mockReturnValue(builder);
  
  builder.insert = vi.fn((data: any) => {
    globalInserts.push({ table, data });
    return builder;
  });
  
  builder.update = vi.fn((data: any) => {
    globalUpdates.push({ table, data });
    return builder;
  });
  
  builder.upsert = vi.fn((data: any) => {
    globalInserts.push({ table, data });
    return builder;
  });

  builder.eq = vi.fn().mockReturnValue(builder);
  builder.gte = vi.fn().mockReturnValue(builder);
  builder.order = vi.fn().mockReturnValue(builder);
  builder.limit = vi.fn().mockReturnValue(builder);

  builder.single = vi.fn().mockImplementation(async () => {
    if (table === "artifacts") {
      if (builder.insert.mock.calls.length > 0) {
        return { data: { id: "artifact-id-123" }, error: null };
      }
      return { data: null, error: null }; // no cache
    }
    if (table === "scoring_profiles") {
      return { data: { version: "1.0", weights: {} }, error: null };
    }
    if (table === "findings") {
      return { data: { id: "finding-id-123" }, error: null };
    }
    return { data: null, error: null };
  });

  builder.then = (resolve: any) => {
    if (table === "evidence") {
      resolve({ data: [{ id: "evidence-id-123" }], error: null });
    } else if (table === "findings" && builder.select.mock.calls.length > 0) {
      resolve({ data: tableMocks.findingsData, error: null });
    } else {
      resolve({ data: null, error: null });
    }
  };
  return builder;
};

const mockSupabaseClient = {
  from: vi.fn((table: string) => createFakeQueryBuilder(table)),
};

vi.mock("@/lib/supabase/local", () => ({
  createLocalClient: vi.fn(() => mockSupabaseClient),
  isLocalMode: true,
}));

describe("runIOCInvestigation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalUpdates.length = 0;
    globalInserts.length = 0;
    tableMocks.findingsData = [];

    (fetchVirusTotal as any).mockResolvedValue({ data: {} });
    (fetchAbuseIPDB as any).mockResolvedValue({ data: {} });
    (fetchWhois as any).mockResolvedValue({ data: {} });
    (fetchIPASN as any).mockResolvedValue({ data: {} });
  });

  afterEach(() => {
  });

  it("1. Happy path: all sources succeed -> ends in COMPLETED with correct final_score", async () => {
    const options = {
      investigationId: "inv-123",
      userId: "user-1",
      target: "8.8.8.8",
      targetType: "IP" as const,
    };

    tableMocks.findingsData = [
      { id: "f1", claim: "Malicious IP", severity: "HIGH", confidence_score: 90, score_contribution: 45, reasoning: "reason" }
    ];

    await runIOCInvestigation(options);

    // Verify it reached COMPLETED
    const completedUpdate = globalUpdates.find(u => u.table === "investigations" && u.data.status === "COMPLETED");
    expect(completedUpdate).toBeDefined();
    
    // Verify final score matches what computeScore would produce
    const expectedScore = computeScore(
      tableMocks.findingsData as any,
      { version: "1.0", weights: {} } as any,
      3, // 3 IP sources: virustotal, abuseipdb, ipasn (wait, domainstring is not enabled for IP)
      3
    ).finalScore;
    expect(completedUpdate.data.final_score).toBe(expectedScore);
  });

  it("2. Partial source failure: one API rejects -> completes with degradation applied", async () => {
    const options = {
      investigationId: "inv-123",
      userId: "user-1",
      target: "8.8.8.8",
      targetType: "IP" as const,
    };

    // Reject AbuseIPDB
    (fetchAbuseIPDB as any).mockRejectedValue(new Error("API timeout"));

    tableMocks.findingsData = [
      { id: "f1", claim: "Malicious IP", severity: "HIGH", confidence_score: 90, score_contribution: 45, reasoning: "reason" }
    ];

    await runIOCInvestigation(options);

    // Verify it still reached COMPLETED
    const completedUpdate = globalUpdates.find(u => u.table === "investigations" && u.data.status === "COMPLETED");
    expect(completedUpdate).toBeDefined();

    // Verify failed_sources array contains abuseipdb
    expect(completedUpdate.data.failed_sources).toEqual([{ source: "abuseipdb", reason: "API timeout" }]);

    // The score should be degraded because successful=2, total=3
    const expectedScore = computeScore(
      tableMocks.findingsData as any,
      { version: "1.0", weights: {} } as any,
      2, 
      3
    ).finalScore;
    expect(completedUpdate.data.final_score).toBe(expectedScore);
  });

  it("3. Total failure: all sources reject -> investigation ends in FAILED", async () => {
    const options = {
      investigationId: "inv-123",
      userId: "user-1",
      target: "8.8.8.8",
      targetType: "IP" as const,
    };

    (fetchVirusTotal as any).mockRejectedValue(new Error("fail"));
    (fetchAbuseIPDB as any).mockRejectedValue(new Error("fail"));
    (fetchIPASN as any).mockRejectedValue(new Error("fail"));

    await runIOCInvestigation(options);

    // Since 0 artifacts were fetched, it should short-circuit to FAILED
    const failedUpdate = globalUpdates.find(u => u.table === "investigations" && u.data.status === "FAILED");
    expect(failedUpdate).toBeDefined();

    // Ensure we didn't score
    const completedUpdate = globalUpdates.find(u => u.table === "investigations" && u.data.status === "COMPLETED");
    expect(completedUpdate).toBeUndefined();
  });

});
