import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { renderToStream } from "@react-pdf/renderer";
import { ForensicBriefing } from "@/lib/pdf/ForensicBriefing";
import type { InvestigationDetail } from "@/lib/pipeline/types";
import React from "react";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Fetch the full investigation
  const { data: inv, error: invError } = await supabase
    .from("investigations")
    .select(`
      id, case_number, target, target_type, status,
      final_score, scoring_profile_version, failed_sources,
      created_at, completed_at,
      artifacts(*),
      evidence(*),
      findings(
        *,
        finding_evidence(evidence(*))
      )
    `)
    .eq("id", id)
    .eq("user_id", user.id)
    .single();

  if (invError || !inv) {
    return NextResponse.json({ error: "Investigation not found" }, { status: 404 });
  }

  // Transform findings to attach evidence directly, same as page.tsx does conceptually
  const formattedFindings = inv.findings.map((f: Record<string, unknown>) => {
    const findingEvidence = f.finding_evidence as Array<{ evidence: unknown }> | undefined;
    return {
      ...f,
      evidence: findingEvidence?.map((fe) => fe.evidence) || []
    };
  });

  const investigationDetail: InvestigationDetail = {
    ...inv,
    findings: formattedFindings,
    // Add other fields to satisfy type but we only need basic ones for PDF
    tags: [],
    notes: [],
    prior_investigations: [],
  } as unknown as InvestigationDetail;

  try {
    // @ts-expect-error - renderToStream expects DocumentProps but custom components that return Document work fine
    const stream = await renderToStream(React.createElement(ForensicBriefing, { investigation: investigationDetail }));

    // Convert NodeJS Readable to Web ReadableStream
    const webStream = new ReadableStream({
      start(controller) {
        stream.on("data", (chunk) => controller.enqueue(chunk));
        stream.on("end", () => controller.close());
        stream.on("error", (err) => controller.error(err));
      }
    });

    return new NextResponse(webStream, {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="NoCap-Forensic-Briefing-${inv.case_number}.pdf"`,
      },
    });
  } catch (error) {
    console.error("PDF Generation Error:", error);
    return NextResponse.json({ error: "Failed to generate PDF" }, { status: 500 });
  }
}
