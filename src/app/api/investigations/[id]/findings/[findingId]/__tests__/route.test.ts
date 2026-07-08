import { describe, it, expect, vi, beforeEach } from "vitest";
import { PATCH } from "../route";
import { NextRequest } from "next/server";

const mockGetUser = vi.fn();
const mockSupabaseQuery = vi.fn();
const mockUpdate = vi.fn();

vi.mock("@/lib/supabase/server", () => ({
  createClient: vi.fn(() => ({
    auth: { getUser: mockGetUser },
    from: vi.fn((table) => {
      const queryObj = {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn().mockImplementation(() => {
          if (table === "investigations" || table === "findings") return mockSupabaseQuery();
          return { data: null, error: null };
        }),
        update: vi.fn().mockImplementation(() => mockUpdate()),
      };
      return queryObj;
    }),
  })),
}));

describe("Findings API - Disposition Updates", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue({ data: { user: { id: "user-1" } } });
  });

  const createRequest = (body: unknown) => {
    return new NextRequest("http://localhost:3000/api/investigations/inv-123/findings/fnd-123", {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  };

  it("rejects when investigation is not found or does not belong to user", async () => {
    mockSupabaseQuery.mockResolvedValue({ data: null, error: null });

    const req = createRequest({ status: "CONFIRMED", note: "this is a valid note" });
    const params = Promise.resolve({ id: "inv-123", findingId: "fnd-123" });
    const res = await PATCH(req, { params });
    
    expect(res.status).toBe(404);
    const json = await res.json();
    expect(json.error).toBe("Not found");
  });

  it("rejects when status is invalid", async () => {
    const req = createRequest({ status: "MAGIC_STATUS" });
    const params = Promise.resolve({ id: "inv-123", findingId: "fnd-123" });
    const res = await PATCH(req, { params });
    
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toBe("Invalid status");
  });

  it("rejects CONFIRMED when note is missing or too short", async () => {
    const req = createRequest({ status: "CONFIRMED", note: "short" });
    const params = Promise.resolve({ id: "inv-123", findingId: "fnd-123" });
    const res = await PATCH(req, { params });
    
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toContain("10 characters");
  });

  it("allows when investigation belongs to user and note is valid", async () => {
    mockSupabaseQuery.mockResolvedValueOnce({ data: { id: "inv-123" }, error: null })
      .mockResolvedValueOnce({ data: { investigation_id: "inv-123", investigations: { user_id: "user-1" } }, error: null });
    
    mockUpdate.mockReturnValue({
      eq: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      single: vi.fn().mockResolvedValue({ data: { id: "fnd-123", status: "CONFIRMED", disposition_note: "valid note text" }, error: null }),
    });

    const req = createRequest({ status: "CONFIRMED", note: "valid note text" });
    const params = Promise.resolve({ id: "inv-123", findingId: "fnd-123" });
    const res = await PATCH(req, { params });
    
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.status).toBe("CONFIRMED");
  });
});
