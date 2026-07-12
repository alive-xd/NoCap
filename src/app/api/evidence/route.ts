import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET(request: NextRequest) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "50"), 200);
  const offset = parseInt(searchParams.get("offset") ?? "0");
  const source = searchParams.get("source");
  const parserName = searchParams.get("parser");
  const findingId = searchParams.get("finding_id");
  const investigationId = searchParams.get("investigation_id");

  // Build the query — only return evidence belonging to the user's investigations
  let query = supabase
    .from("evidence")
    .select(`
      id, fact_type, fact_value, parser_name, parser_version, created_at,
      artifact_id,
      artifacts!inner(
        id, source, investigation_id,
        investigations!inner(
          id, case_number, target, user_id
        )
      )
    `)
    .eq("artifacts.investigations.user_id", user.id)
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (source) query = query.eq("artifacts.source", source);
  if (parserName) query = query.eq("parser_name", parserName);
  if (investigationId) query = query.eq("artifacts.investigation_id", investigationId);

  // Filter by finding_id (evidence linked to a specific finding)
  if (findingId) {
    const { data: feRows } = await supabase
      .from("finding_evidence")
      .select("evidence_id")
      .eq("finding_id", findingId);

    const evidenceIds = (feRows ?? []).map((r: { evidence_id: string }) => r.evidence_id);
    if (evidenceIds.length > 0) {
      query = query.in("id", evidenceIds);
    } else {
      return NextResponse.json({ evidence: [], total: 0 });
    }
  }

  const { data, error, count } = await query;
  if (error) {
    console.error("[evidence] GET error:", error);
    return NextResponse.json({ error: "Failed to fetch evidence" }, { status: 500 });
  }

  return NextResponse.json({ evidence: data ?? [], total: count ?? 0, offset, limit });
}
