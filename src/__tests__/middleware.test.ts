import { describe, it, expect, vi } from "vitest";
import { proxy } from "../middleware";
import { NextRequest } from "next/server";

// Mock @supabase/ssr so it doesn't complain about env vars
vi.mock("@supabase/ssr", () => ({
  createServerClient: vi.fn(() => ({
    auth: {
      getUser: vi.fn().mockResolvedValue({ data: { user: null } }),
    },
  })),
}));

describe("middleware.ts - CSRF check", () => {
  const createMockRequest = (method: string, headers: Record<string, string>) => {
    const nextUrl = new URL("http://localhost:3000/api/some-endpoint");
    const reqHeaders = new Headers();
    for (const [k, v] of Object.entries(headers)) {
      reqHeaders.set(k, v);
    }
    // Need to set host header for the check to work
    if (!reqHeaders.has("host")) {
      reqHeaders.set("host", "localhost:3000");
    }

    return new NextRequest(nextUrl.toString(), {
      method,
      headers: reqHeaders,
    });
  };

  it("passes mutating request with matching Origin and Referer", async () => {
    const req = createMockRequest("POST", {
      origin: "http://localhost:3000",
      referer: "http://localhost:3000/some-path",
    });

    const res = await proxy(req);
    // Should not return 403. It will return a 307 redirect to /login since no user,
    // or a 200/NextResponse.next(). 
    expect(res.status).not.toBe(403);
  });

  it("rejects mutating request with mismatched Origin", async () => {
    const req = createMockRequest("POST", {
      origin: "http://evil.com",
      referer: "http://localhost:3000/some-path",
    });

    const res = await proxy(req);
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain("CSRF verification failed");
  });

  it("rejects mutating request with mismatched Referer", async () => {
    const req = createMockRequest("DELETE", {
      origin: "http://localhost:3000",
      referer: "http://evil.com/some-path",
    });

    const res = await proxy(req);
    expect(res.status).toBe(403);
  });

  it("passes mutating request with no Origin/Referer (based on current code behavior)", async () => {
    // Current code: `const isOriginValid = originHost ? originHost === host : true;`
    // Meaning missing Origin/Referer is allowed (true).
    const req = createMockRequest("PUT", {});
    const res = await proxy(req);
    expect(res.status).not.toBe(403);
  });

  it("passes non-mutating request with mismatched Origin", async () => {
    const req = createMockRequest("GET", {
      origin: "http://evil.com",
    });
    const res = await proxy(req);
    // GET requests skip the CSRF check
    expect(res.status).not.toBe(403);
  });
});
