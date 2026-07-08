import { describe, it, expect, vi, beforeEach } from "vitest";
import { GET } from "../route";
import { NextRequest } from "next/server";

const mockGetUser = vi.fn();
const mockSupabaseQuery = vi.fn();

vi.mock("@/lib/supabase/server", () => ({
  createClient: vi.fn(() => ({
    auth: { getUser: mockGetUser },
    from: vi.fn((table) => {
      const queryObj = {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        order: vi.fn().mockReturnThis(),
        single: vi.fn().mockImplementation(() => {
          if (table === "investigations") return mockSupabaseQuery();
          return { data: null, error: null };
        }),
      };
      return queryObj;
    }),
  })),
}));

describe("GET /api/investigations/[id] - Demo Route RLS behavior", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const createRequest = () => {
    return new NextRequest("http://localhost:3000/api/investigations/123", {
      method: "GET",
    });
  };

  it("returns 404 if investigation is not found (or blocked by RLS for demo)", async () => {
    // Unauthenticated user
    mockGetUser.mockResolvedValue({ data: { user: null } });
    
    // Simulate RLS blocking the read because is_public_demo is false
    mockSupabaseQuery.mockResolvedValue({ data: null, error: { message: "Row not found" } });

    const req = createRequest();
    const params = Promise.resolve({ id: "123" });
    const res = await GET(req, { params });
    
    expect(res.status).toBe(404);
  });

  it("returns 200 if investigation is found (RLS allowed it due to is_public_demo = true)", async () => {
    // Unauthenticated user
    mockGetUser.mockResolvedValue({ data: { user: null } });
    
    // Simulate RLS allowing the read because is_public_demo is true
    mockSupabaseQuery.mockResolvedValue({ data: { id: "123", target: "example.com" }, error: null });

    const req = createRequest();
    const params = Promise.resolve({ id: "123" });
    const res = await GET(req, { params });
    
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.id).toBe("123");
  });
});
