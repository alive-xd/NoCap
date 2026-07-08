import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { isLocalMode } from "@/lib/supabase/local";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const supabase = await createClient();

  // Fetch the investigation, enforcing is_public_demo if not in local mode
  let query = supabase
    .from("investigations")
    .select("*")
    .eq("id", id);

  if (!isLocalMode) {
    query = query.eq("is_public_demo", true);
  }

  const { data: investigation, error: invError } = await query.single();

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

  // Evidence (all evidence for this investigation, regardless of findings)
  const artifactIds = (artifacts ?? []).map((a: { id: string }) => a.id);
  const { data: allEvidence } = artifactIds.length > 0
    ? await supabase.from("evidence").select("*").in("artifact_id", artifactIds)
    : { data: [] };

  return NextResponse.json({
    ...investigation,
    artifacts: artifacts ?? [],
    findings: findingsWithEvidence,
    metrics: metrics ?? null,
    notes: [], // Stripped for demo
    tags: [], // Stripped for demo
    prior_investigations: [], // Stripped for demo
    all_evidence: allEvidence ?? [],
  });
}
