import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

const VALID_STATUSES = ["FLAGGED", "CONFIRMED", "CLEARED", "UNDER_REVIEW"];

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string; findingId: string }> }
) {
  const { id, findingId } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const payload = await request.json() as { status: string; note?: string };
  const { status, note } = payload;

  if (!status || !VALID_STATUSES.includes(status)) {
    return NextResponse.json({ error: "Invalid status" }, { status: 400 });
  }

  if (["CONFIRMED", "CLEARED"].includes(status)) {
    if (!note || note.trim().length < 10) {
      return NextResponse.json({ error: "A note of at least 10 characters is required for this status" }, { status: 400 });
    }
  }

  // Verify investigation ownership
  const { data: inv } = await supabase
    .from("investigations")
    .select("id")
    .eq("id", id)
    .eq("user_id", user.id)
    .single();
  if (!inv) return NextResponse.json({ error: "Not found" }, { status: 404 });

  // Explicit ownership check for the finding itself
  const { data: findingCheck } = await supabase
    .from("findings")
    .select("investigation_id, investigations!inner(user_id)")
    .eq("id", findingId)
    .single();
    
  if (!findingCheck || (findingCheck.investigations as any)?.user_id !== user.id) {
    return NextResponse.json({ error: "Unauthorized to modify this finding" }, { status: 403 });
  }

  const { data: finding, error } = await supabase
    .from("findings")
    .update({ 
      status: status, 
      disposition_note: note ? note.trim() : null 
    })
    .eq("id", findingId)
    .eq("investigation_id", id)
    .select()
    .single();

  if (error) {
    console.error("[findings] PATCH error:", error);
    return NextResponse.json({ error: "Failed to update finding" }, { status: 500 });
  }
  return NextResponse.json(finding);
}
