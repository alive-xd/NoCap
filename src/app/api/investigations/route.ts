import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  createInvestigationRecord,
  runIOCInvestigation,
  runPhishingInvestigation,
  runAttackSurfaceInvestigation,
  runCVEInvestigation,
} from "@/lib/investigation/orchestrator";
import { detectIOCType } from "@/lib/investigation/iocDetector";

export async function POST(request: NextRequest) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json() as {
    target: string;
    investigationType?: "ioc" | "phishing" | "attack_surface";
    rawEmailHeaders?: string;
  };

  const { target, investigationType = "ioc", rawEmailHeaders } = body;

  if (!target || typeof target !== "string" || !target.trim()) {
    return NextResponse.json({ error: "target cannot be empty" }, { status: 400 });
  }

  // ── Rate Limiting ──────────────────────────────────────────────────────────
  const oneMinuteAgo = new Date(Date.now() - 60 * 1000).toISOString();
  const { count: recentCount, error: countError } = await supabase
    .from("investigations")
    .select("id", { count: "exact", head: true })
    .eq("user_id", user.id)
    .gte("created_at", oneMinuteAgo);

  if (!countError && recentCount !== null && recentCount >= 5) {
    return NextResponse.json(
      { error: "Rate limit exceeded (max 5 investigations per minute). Please wait before trying again." },
      { status: 429 }
    );
  }

  const targetType = detectIOCType(target.trim());

  try {
    const investigationId = await createInvestigationRecord(
      user.id,
      target.trim(),
      targetType
    );

    // Run the pipeline asynchronously — return immediately with the investigation ID
    // The client polls /api/investigations/[id] for status updates
    const runPipeline = async () => {
      try {
        if (targetType === "CVE") {
          await runCVEInvestigation({
            investigationId,
            userId: user.id,
            target: target.trim(),
            targetType: "CVE",
          });
        } else if (investigationType === "phishing") {
          await runPhishingInvestigation({
            investigationId,
            userId: user.id,
            target: target.trim(),
            targetType,
            rawEmailHeaders,
          });
        } else if (investigationType === "attack_surface") {
          await runAttackSurfaceInvestigation({
            investigationId,
            userId: user.id,
            target: target.trim(),
            targetType,
          });
        } else {
          await runIOCInvestigation({
            investigationId,
            userId: user.id,
            target: target.trim(),
            targetType,
          });
        }
      } catch (err) {
        console.error("[investigations] Pipeline error:", err);
      }
    };

    // Fire and forget — don't await
    runPipeline();

    return NextResponse.json({ id: investigationId, status: "CREATED" }, { status: 202 });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "50"), 100);
  const offset = parseInt(searchParams.get("offset") ?? "0");
  const status = searchParams.get("status");
  const tag = searchParams.get("tag");
  const search = searchParams.get("q");

  let query = supabase
    .from("investigations")
    .select(`
      id, case_number, target, target_type, status,
      final_score, scoring_profile_version, failed_sources,
      created_at, completed_at,
      investigation_tags(tags(name))
    `)
    .eq("user_id", user.id)
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (status) query = query.eq("status", status);
  if (search) {
    const sanitized = search.replace(/[()",]/g, "");
    query = query.or(`target.ilike.%${sanitized}%,case_number.ilike.%${sanitized}%`);
  }

  const { data, error, count } = await query;

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  // Group by Today / Yesterday / This Week / Archived
  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterdayStart = new Date(todayStart.getTime() - 86400000);
  const weekStart = new Date(todayStart.getTime() - 6 * 86400000);

  const grouped = {
    today: [] as typeof data,
    yesterday: [] as typeof data,
    this_week: [] as typeof data,
    archived: [] as typeof data,
  };

  for (const inv of data ?? []) {
    const created = new Date(inv.created_at);
    if (created >= todayStart) grouped.today.push(inv);
    else if (created >= yesterdayStart) grouped.yesterday.push(inv);
    else if (created >= weekStart) grouped.this_week.push(inv);
    else grouped.archived.push(inv);
  }

  return NextResponse.json({ grouped, total: count, offset, limit });
}
