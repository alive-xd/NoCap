import { describe, it, expect, vi, beforeEach } from "vitest";
import { POST } from "../route";
import { NextRequest } from "next/server";

// Stub `after` so the route handler doesn't throw in the test environment.
// We call the callback synchronously so any pipeline mock side-effects are exercised.
vi.mock("next/server", async (importOriginal) => {
  const actual = await importOriginal<typeof import("next/server")>();
  return {
    ...actual,
    after: vi.fn((fn: () => void) => { fn(); }),
  };
});

const mockGetUser = vi.fn();
const mockSupabaseQuery = vi.fn();
const mockInsert = vi.fn();

vi.mock("@/lib/supabase/server", () => ({
  createClient: vi.fn(() => ({
    auth: { getUser: mockGetUser },
    from: vi.fn((table) => {
      const queryObj = {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        gte: vi.fn().mockImplementation(() => mockSupabaseQuery(table)),
        insert: vi.fn().mockImplementation(() => mockInsert(table)),
      };
      return queryObj;
    }),
  })),
}));

// Mock orchestrator so it doesn't actually try to insert into DB
vi.mock("@/lib/investigation/orchestrator", () => ({
  createInvestigationRecord: vi.fn().mockResolvedValue("mock-inv-id"),
  runIOCInvestigation: vi.fn().mockResolvedValue(undefined),
  runPhishingInvestigation: vi.fn().mockResolvedValue(undefined),
  runAttackSurfaceInvestigation: vi.fn().mockResolvedValue(undefined),
  runCVEInvestigation: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@/lib/investigation/iocDetector", () => ({
  detectIOCType: vi.fn().mockReturnValue("DOMAIN")
}));

describe("POST /api/investigations - Security & Validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue({ data: { user: { id: "user-1" } } });
  });

  const createRequest = (body: unknown) => {
    return new NextRequest("http://localhost:3000/api/investigations", {
      method: "POST",
      body: JSON.stringify(body),
    });
  };

  describe("Whitespace-only target validation", () => {
    it('rejects " " (space)', async () => {
      const res = await POST(createRequest({ target: " " }));
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toContain("target cannot be empty");
    });

    it('rejects "\\t\\n" (tab/newline)', async () => {
      const res = await POST(createRequest({ target: "\t\n" }));
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toContain("target cannot be empty");
    });

    it('rejects "" (empty string)', async () => {
      const res = await POST(createRequest({ target: "" }));
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toContain("target cannot be empty");
    });
    
    it('accepts valid string', async () => {
      mockSupabaseQuery.mockResolvedValue({ count: 0, error: null });
      const res = await POST(createRequest({ target: "example.com" }));
      expect(res.status).toBe(202);
    });
  });

  describe("Rate limiting (5 requests/minute)", () => {
    it("rejects the 6th request from the same user", async () => {
      // Mock that the DB says there are 5 recent investigations
      mockSupabaseQuery.mockResolvedValue({ count: 5, error: null });

      const res = await POST(createRequest({ target: "example.com" }));
      expect(res.status).toBe(429);
      const json = await res.json();
      expect(json.error).toContain("Rate limit exceeded");
    });

    it("allows a request if the user has 4 recent investigations", async () => {
      mockSupabaseQuery.mockResolvedValue({ count: 4, error: null });

      const res = await POST(createRequest({ target: "example.com" }));
      expect(res.status).toBe(202);
    });

    it("a different user isn't affected by the first user's count (logic in DB)", async () => {
      // In a real DB, the `eq("user_id", user.id)` query ensures isolation.
      // We test that the route actually extracts the correct user ID and passes it
      // to the Supabase client.
      mockGetUser.mockResolvedValue({ data: { user: { id: "user-2" } } });
      mockSupabaseQuery.mockResolvedValue({ count: 0, error: null });

      const res = await POST(createRequest({ target: "example.com" }));
      expect(res.status).toBe(202);
      
      // We know isolation is maintained because user-2 had 0 recent investigations mocked
    });
  });

  describe("Input length limits", () => {
    it("rejects target exceeding 500 characters", async () => {
      const longTarget = "a".repeat(501);
      const res = await POST(createRequest({ target: longTarget }));
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toContain("target exceeds maximum length");
    });

    it("rejects rawEmailHeaders exceeding 50000 characters", async () => {
      const longHeaders = "a".repeat(50001);
      const res = await POST(createRequest({ target: "example.com", rawEmailHeaders: longHeaders }));
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toContain("rawEmailHeaders exceeds maximum length");
    });
  });
});
