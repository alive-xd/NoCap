import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { detectIOCType } from "@/lib/investigation/iocDetector";
import {
  createInvestigationRecord,
  runIOCInvestigation,
  runPhishingInvestigation,
  runAttackSurfaceInvestigation,
} from "@/lib/investigation/orchestrator";

export async function POST(request: NextRequest) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await request.json() as {
    targets: string[];
    investigationType?: "ioc" | "phishing" | "attack_surface";
  };

  const { targets, investigationType = "ioc" } = body;

  if (!Array.isArray(targets) || targets.length === 0) {
    return NextResponse.json({ error: "targets array is required" }, { status: 400 });
  }

  if (targets.length > 20) {
    return NextResponse.json({ error: "Maximum 20 targets per batch" }, { status: 400 });
  }

  // ── Rate Limiting ──────────────────────────────────────────────────────────
  const oneMinuteAgo = new Date(Date.now() - 60 * 1000).toISOString();
  const { count: recentCount, error: countError } = await supabase
    .from("investigations")
    .select("id", { count: "exact", head: true })
    .eq("user_id", user.id)
    .gte("created_at", oneMinuteAgo);

  if (!countError && recentCount !== null && (recentCount + targets.length) > 5) {
    return NextResponse.json(
      { error: "Rate limit exceeded (max 5 investigations per minute). Please wait before trying again." },
      { status: 429 }
    );
  }

  // Create all investigation records first (synchronous — needed for response)
  const results: Array<{ target: string; id: string; status: string; error?: string }> = [];

  for (const target of targets) {
    if (!target?.trim()) continue;
    try {
      const targetType = detectIOCType(target.trim());
      const id = await createInvestigationRecord(user.id, target.trim(), targetType);
      results.push({ target: target.trim(), id, status: "CREATED" });
    } catch (err) {
      results.push({
        target: target.trim(),
        id: "",
        status: "ERROR",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // Fire all pipelines in parallel (no await)
  const runAll = async () => {
    await Promise.allSettled(
      results
        .filter((r) => r.id)
        .map(async (r) => {
          const targetType = detectIOCType(r.target);
          if (investigationType === "phishing") {
            return runPhishingInvestigation({ investigationId: r.id, userId: user.id, target: r.target, targetType });
          } else if (investigationType === "attack_surface") {
            return runAttackSurfaceInvestigation({ investigationId: r.id, userId: user.id, target: r.target, targetType });
          }
          return runIOCInvestigation({ investigationId: r.id, userId: user.id, target: r.target, targetType });
        })
    );
  };

  runAll();

  return NextResponse.json({ results }, { status: 202 });
}
