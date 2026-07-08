import { describe, it, expect, vi, beforeEach } from "vitest";
import { PATCH, DELETE } from "../route";
import { NextRequest } from "next/server";

const mockGetUser = vi.fn();
const mockSupabaseQuery = vi.fn();
const mockUpdate = vi.fn();
const mockDelete = vi.fn();

vi.mock("@/lib/supabase/server", () => ({
  createClient: vi.fn(() => ({
    auth: { getUser: mockGetUser },
    from: vi.fn((table) => {
      const queryObj = {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn().mockImplementation(() => {
          if (table === "investigations" || table === "notes") return mockSupabaseQuery();
          return { data: null, error: null };
        }),
        update: vi.fn().mockImplementation(() => mockUpdate()),
        delete: vi.fn().mockImplementation(() => mockDelete()),
      };
      return queryObj;
    }),
  })),
}));

describe("Notes API - Ownership Guards", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue({ data: { user: { id: "user-1" } } });
  });

  const createRequest = (method: string, body: unknown) => {
    return new NextRequest("http://localhost:3000/api/investigations/123/notes", {
      method,
      body: JSON.stringify(body),
    });
  };

  it("PATCH rejects when investigation is not found or does not belong to user", async () => {
    // Mock single() to return nothing (meaning not found or wrong owner)
    mockSupabaseQuery.mockResolvedValue({ data: null, error: null });

    const req = createRequest("PATCH", { noteId: "note-1", content: "updated" });
    const params = Promise.resolve({ id: "inv-123" });
    const res = await PATCH(req, { params });
    
    expect(res.status).toBe(404);
    const json = await res.json();
    expect(json.error).toBe("Not found");
  });

  it("PATCH allows when investigation belongs to user", async () => {
    mockSupabaseQuery.mockResolvedValueOnce({ data: { id: "inv-123" }, error: null })
      .mockResolvedValueOnce({ data: { investigation_id: "inv-123", investigations: { user_id: "user-1" } }, error: null });
    mockUpdate.mockReturnValue({
      eq: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      single: vi.fn().mockResolvedValue({ data: { id: "note-1" }, error: null }),
    });

    const req = createRequest("PATCH", { noteId: "note-1", content: "updated" });
    const params = Promise.resolve({ id: "inv-123" });
    const res = await PATCH(req, { params });
    
    expect(res.status).toBe(200);
  });

  it("DELETE rejects when investigation is not found or does not belong to user", async () => {
    mockSupabaseQuery.mockResolvedValue({ data: null, error: null });

    const req = createRequest("DELETE", { noteId: "note-1" });
    const params = Promise.resolve({ id: "inv-123" });
    const res = await DELETE(req, { params });
    
    expect(res.status).toBe(404);
  });

  it("DELETE allows when investigation belongs to user", async () => {
    mockSupabaseQuery.mockResolvedValueOnce({ data: { id: "inv-123" }, error: null })
      .mockResolvedValueOnce({ data: { investigation_id: "inv-123", investigations: { user_id: "user-1" } }, error: null });
    mockDelete.mockReturnValue({
      eq: vi.fn().mockReturnThis(),
    });

    const req = createRequest("DELETE", { noteId: "note-1" });
    const params = Promise.resolve({ id: "inv-123" });
    const res = await DELETE(req, { params });
    
    expect(res.status).toBe(200);
  });
});
