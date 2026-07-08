/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runAttackSurfaceInvestigation, runCVEInvestigation } from "../orchestrator";
import { fetchCrtSh } from "@/lib/apis/crtsh";
import { searchGitHubCode } from "@/lib/apis/github-search";
import { fetchNVDById } from "@/lib/apis/nvd";

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
  builder.inner = vi.fn().mockReturnValue(builder);

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

describe("runAttackSurfaceInvestigation", () => {
  const originalFetch = global.fetch;
  
  beforeEach(() => {
    vi.clearAllMocks();
    globalUpdates.length = 0;
    globalInserts.length = 0;
    tableMocks.findingsData = [];

    (fetchCrtSh as any).mockResolvedValue({ raw: [], subdomains: [] });
    (searchGitHubCode as any).mockResolvedValue({ total_count: 0, items: [] });
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("1. Target host returns a non-2xx status (500) -> pipeline completes properly without crashing", async () => {
    // Mock fetch for OpenRouter (so pipeline doesn't fail there) and probeHTTP
    global.fetch = vi.fn().mockImplementation(async (url: any) => {

      // For probeHTTP
      return {
        status: 500,
        ok: false,
        headers: new Map(), // Provide empty Map-like iterable for headers.forEach
        json: async () => ({}),
        text: async () => ""
      };
    });

    const options = {
      investigationId: "inv-123",
      userId: "user-1",
      target: "example.com",
      targetType: "DOMAIN" as const,
    };

    await runAttackSurfaceInvestigation(options);

    const completedUpdate = globalUpdates.find(u => u.table === "investigations" && u.data.status === "COMPLETED");
    expect(completedUpdate).toBeDefined();
    
    // Check evidence was inserted with status 500
    const evidenceInsert = globalInserts.find(i => i.table === "evidence" && Array.isArray(i.data) && i.data.some((row: any) => row.fact_type === "status_code" && row.fact_value === 500));
    expect(evidenceInsert).toBeDefined();
  });

  it("2. probeHTTP fetch itself rejects (e.g. connection refused) -> recorded as failed source, completes", async () => {
    global.fetch = vi.fn().mockImplementation(async (url: any) => {

      throw new Error("Connection refused");
    });

    const options = {
      investigationId: "inv-123",
      userId: "user-1",
      target: "example.com",
      targetType: "DOMAIN" as const,
    };

    await runAttackSurfaceInvestigation(options);

    const completedUpdate = globalUpdates.find(u => u.table === "investigations" && u.data.status === "COMPLETED");
    expect(completedUpdate).toBeDefined();
    
    // Expect failed source
    expect(completedUpdate.data.failed_sources).toContainEqual({
      source: "http_fingerprint",
      reason: "HTTP probe failed"
    });
  });
});

describe("runCVEInvestigation", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.clearAllMocks();
    globalUpdates.length = 0;
    globalInserts.length = 0;
    tableMocks.findingsData = [];

    (fetchNVDById as any).mockResolvedValue({ vulnerabilities: [] });
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("1. CISA KEV fetch rejects/times out -> falls back to false without crashing", async () => {
    global.fetch = vi.fn().mockImplementation(async (url: string) => {

      if (url.includes("cisa.gov")) {
        throw new Error("Timeout");
      }
      if (url.includes("exploit-db.com")) {
        return { ok: true, text: async () => "nothing" };
      }
      return { ok: true };
    });

    const options = {
      investigationId: "inv-123",
      userId: "user-1",
      target: "CVE-2023-1234",
      targetType: "CVE" as const,
    };

    await runCVEInvestigation(options);

    const artifactInsert = globalInserts.find(i => i.table === "artifacts" && i.data.source === "nvd");
    expect(artifactInsert).toBeDefined();
    expect(artifactInsert.data.raw_response.in_cisa_kev).toBe(false);

    const completedUpdate = globalUpdates.find(u => u.table === "investigations" && u.data.status === "COMPLETED");
    expect(completedUpdate).toBeDefined();
  });

  it("2. Exploit-DB fetch returns malformed unexpected format -> falls back safely", async () => {
    global.fetch = vi.fn().mockImplementation(async (url: string) => {

      if (url.includes("cisa.gov")) {
        return { ok: true, json: async () => ({ vulnerabilities: [] }) };
      }
      if (url.includes("exploit-db.com")) {
        // Exploit-DB fetch in the code does: await res.text() and then .includes()
        // If it returns malformed content, .includes() won't match, so it's handled safely.
        // What if text() fails?
        return { ok: true, text: async () => { throw new Error("Stream error"); } };
      }
      return { ok: true };
    });

    const options = {
      investigationId: "inv-123",
      userId: "user-1",
      target: "CVE-2023-1234",
      targetType: "CVE" as const,
    };

    await runCVEInvestigation(options);

    const artifactInsert = globalInserts.find(i => i.table === "artifacts" && i.data.source === "nvd");
    expect(artifactInsert.data.raw_response.has_known_exploit).toBe(false);

    const completedUpdate = globalUpdates.find(u => u.table === "investigations" && u.data.status === "COMPLETED");
    expect(completedUpdate).toBeDefined();
  });

  it("3. Both external checks fail simultaneously -> investigation still reaches COMPLETED", async () => {
    global.fetch = vi.fn().mockImplementation(async (url: string) => {

      if (url.includes("cisa.gov")) {
        throw new Error("Failed");
      }
      if (url.includes("exploit-db.com")) {
        throw new Error("Failed");
      }
      return { ok: true };
    });

    const options = {
      investigationId: "inv-123",
      userId: "user-1",
      target: "CVE-2023-1234",
      targetType: "CVE" as const,
    };

    await runCVEInvestigation(options);

    const artifactInsert = globalInserts.find(i => i.table === "artifacts" && i.data.source === "nvd");
    expect(artifactInsert.data.raw_response.in_cisa_kev).toBe(false);
    expect(artifactInsert.data.raw_response.has_known_exploit).toBe(false);

    // It completes normally because NVD succeeded and CISA/Exploit-DB just degrade gracefully.
    const completedUpdate = globalUpdates.find(u => u.table === "investigations" && u.data.status === "COMPLETED");
    expect(completedUpdate).toBeDefined();
  });
});
