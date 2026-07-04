import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  // Fetch the investigation
  const { data: investigation, error: invError } = await supabase
    .from("investigations")
    .select("*")
    .eq("id", id)
    .eq("user_id", user.id)
    .single();

  if (invError || !investigation) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  // Artifacts
  const { data: artifacts } = await supabase
    .from("artifacts")
    .select("*")
    .eq("investigation_id", id)
    .order("fetched_at", { ascending: true });

  // Findings with evidence
  const { data: findings } = await supabase
    .from("findings")
    .select(`
      *,
      finding_evidence(
        evidence(
          id, fact_type, fact_value, parser_name, parser_version, created_at,
          artifact_id
        )
      )
    `)
    .eq("investigation_id", id)
    .order("score_contribution", { ascending: false });

  // Flatten finding_evidence joins
  const findingsWithEvidence = (findings ?? []).map((f: Record<string, unknown>) => ({
    ...f,
    evidence: ((f.finding_evidence ?? []) as Array<{ evidence: unknown }>).map((fe) => fe.evidence),
  }));

  // Metrics
  const { data: metrics } = await supabase
    .from("investigation_metrics")
    .select("*")
    .eq("investigation_id", id)
    .single();

  // Notes
  const { data: notes } = await supabase
    .from("notes")
    .select("*")
    .eq("investigation_id", id)
    .order("created_at", { ascending: false });

  // Tags
  const { data: tagRows } = await supabase
    .from("investigation_tags")
    .select("tags(id, name)")
    .eq("investigation_id", id);

  const tags = (tagRows ?? []).map((r: { tags: unknown }) => r.tags);

  // IOC History — prior investigations for the same target
  const { data: priorInvestigations } = await supabase
    .from("investigations")
    .select("id, case_number, final_score, created_at, status")
    .eq("target", investigation.target)
    .eq("user_id", user.id)
    .neq("id", id)
    .order("created_at", { ascending: false })
    .limit(5);

  return NextResponse.json({
    ...investigation,
    artifacts: artifacts ?? [],
    findings: findingsWithEvidence,
    metrics: metrics ?? null,
    notes: notes ?? [],
    tags,
    prior_investigations: priorInvestigations ?? [],
  });
}
