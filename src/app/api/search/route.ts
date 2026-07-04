import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET(request: NextRequest) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const query = searchParams.get("q") ?? "";
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "20"), 50);

  if (!query.trim()) {
    return NextResponse.json({ results: [] });
  }

  const sanitizedQuery = query.replace(/[()",]/g, "");

  // Search investigations by target, case_number
  const { data: investigations } = await supabase
    .from("investigations")
    .select("id, case_number, target, target_type, status, final_score, created_at")
    .eq("user_id", user.id)
    .or(`target.ilike.%${sanitizedQuery}%,case_number.ilike.%${sanitizedQuery}%`)
    .order("created_at", { ascending: false })
    .limit(limit);

  // Search notes content
  const { data: noteMatches } = await supabase
    .from("notes")
    .select(`
      id, content, investigation_id,
      investigations!inner(id, case_number, target, user_id)
    `)
    .eq("investigations.user_id", user.id)
    .ilike("content", `%${query}%`)
    .limit(10);

  // Search finding claims
  const { data: findingMatches } = await supabase
    .from("findings")
    .select(`
      id, claim, severity, investigation_id,
      investigations!inner(id, case_number, target, user_id)
    `)
    .eq("investigations.user_id", user.id)
    .ilike("claim", `%${query}%`)
    .limit(10);

  return NextResponse.json({
    results: {
      investigations: investigations ?? [],
      notes: noteMatches ?? [],
      findings: findingMatches ?? [],
    },
  });
}
