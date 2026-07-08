import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { data: inv } = await supabase
    .from("investigations")
    .select("id")
    .eq("id", id)
    .eq("user_id", user.id)
    .single();
  if (!inv) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { tagName } = await request.json() as { tagName: string };
  if (!tagName?.trim()) {
    return NextResponse.json({ error: "tagName is required" }, { status: 400 });
  }

  // Upsert the tag
  const { data: tag, error: tagError } = await supabase
    .from("tags")
    .upsert({ user_id: user.id, name: tagName.trim() }, { onConflict: "user_id,name" })
    .select()
    .single();

  if (tagError || !tag) {
    return NextResponse.json({ error: tagError?.message ?? "Tag error" }, { status: 500 });
  }

  // Link to investigation
  await supabase
    .from("investigation_tags")
    .upsert({ investigation_id: id, tag_id: tag.id });

  return NextResponse.json(tag, { status: 201 });
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { tagId } = await request.json() as { tagId: string };

  const { data: inv } = await supabase
    .from("investigations")
    .select("id")
    .eq("id", id)
    .eq("user_id", user.id)
    .single();
  if (!inv) return NextResponse.json({ error: "Not found" }, { status: 404 });

  // Explicit ownership check for the tag itself
  const { data: tagCheck } = await supabase
    .from("tags")
    .select("user_id")
    .eq("id", tagId)
    .single();
    
  if (!tagCheck || tagCheck.user_id !== user.id) {
    return NextResponse.json({ error: "Unauthorized to modify this tag" }, { status: 403 });
  }

  await supabase
    .from("investigation_tags")
    .delete()
    .eq("investigation_id", id)
    .eq("tag_id", tagId);

  return NextResponse.json({ success: true });
}
