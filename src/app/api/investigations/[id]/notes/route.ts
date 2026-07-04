import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  // Verify investigation ownership
  const { data: inv } = await supabase
    .from("investigations")
    .select("id")
    .eq("id", id)
    .eq("user_id", user.id)
    .single();
  if (!inv) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { data: notes } = await supabase
    .from("notes")
    .select("*")
    .eq("investigation_id", id)
    .order("created_at", { ascending: false });

  return NextResponse.json(notes ?? []);
}

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

  const { content } = await request.json() as { content: string };
  if (!content?.trim()) {
    return NextResponse.json({ error: "content is required" }, { status: 400 });
  }

  const { data: note, error } = await supabase
    .from("notes")
    .insert({ investigation_id: id, content: content.trim() })
    .select()
    .single();

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json(note, { status: 201 });
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { noteId, content } = await request.json() as { noteId: string; content: string };

  const { data: inv } = await supabase
    .from("investigations")
    .select("id")
    .eq("id", id)
    .eq("user_id", user.id)
    .single();
  if (!inv) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { data: note, error } = await supabase
    .from("notes")
    .update({ content: content.trim(), updated_at: new Date().toISOString() })
    .eq("id", noteId)
    .eq("investigation_id", id)
    .select()
    .single();

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json(note);
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { noteId } = await request.json() as { noteId: string };
  if (!noteId) {
    return NextResponse.json({ error: "noteId is required" }, { status: 400 });
  }

  // Verify parent investigation belongs to current user
  const { data: inv } = await supabase
    .from("investigations")
    .select("id")
    .eq("id", id)
    .eq("user_id", user.id)
    .single();
  if (!inv) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const { error } = await supabase
    .from("notes")
    .delete()
    .eq("id", noteId)
    .eq("investigation_id", id);

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ success: true });
}
