import { describe, it, expect, vi, beforeEach } from "vitest";
import { DELETE } from "../route";
import { NextRequest } from "next/server";

const mockGetUser = vi.fn();
const mockSupabaseQuery = vi.fn();
const mockDelete = vi.fn();

vi.mock("@/lib/supabase/server", () => ({
  createClient: vi.fn(() => ({
    auth: { getUser: mockGetUser },
    from: vi.fn((table) => {
      const queryObj = {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn().mockImplementation(() => {
          if (table === "investigations") return mockSupabaseQuery();
          return { data: null, error: null };
        }),
        delete: vi.fn().mockImplementation(() => mockDelete()),
      };
      return queryObj;
    }),
  })),
}));

describe("Tags API - Ownership Guards", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue({ data: { user: { id: "user-1" } } });
  });

  const createRequest = (method: string, body: unknown) => {
    return new NextRequest("http://localhost:3000/api/investigations/123/tags", {
      method,
      body: JSON.stringify(body),
    });
  };

  it("DELETE rejects when investigation is not found or does not belong to user", async () => {
    mockSupabaseQuery.mockResolvedValue({ data: null, error: null });

    const req = createRequest("DELETE", { tagId: "tag-1" });
    const params = Promise.resolve({ id: "inv-123" });
    const res = await DELETE(req, { params });
    
    expect(res.status).toBe(404);
  });

  it("DELETE allows when investigation belongs to user", async () => {
    mockSupabaseQuery.mockResolvedValue({ data: { id: "inv-123" }, error: null });
    mockDelete.mockReturnValue({
      eq: vi.fn().mockReturnThis(),
    });

    const req = createRequest("DELETE", { tagId: "tag-1" });
    const params = Promise.resolve({ id: "inv-123" });
    const res = await DELETE(req, { params });
    
    expect(res.status).toBe(200);
  });
});
