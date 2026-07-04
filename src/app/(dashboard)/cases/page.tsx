import { createClient } from "@/lib/supabase/server";
import Link from "next/link";
import type { Investigation } from "@/lib/pipeline/types";

function scoreColor(score: number | null) {
  if (score === null) return "var(--text-tertiary)";
  if (score >= 75) return "var(--severity-critical)";
  if (score >= 50) return "var(--severity-high)";
  if (score >= 25) return "var(--severity-medium)";
  return "var(--severity-low)";
}

export default async function CasesPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const { q = "" } = await searchParams;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  let query = supabase
    .from("investigations")
    .select(`
      id, case_number, target, target_type, status, final_score, created_at, completed_at,
      investigation_tags(tags(name))
    `)
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (q.trim()) {
    const sanitized = q.replace(/[()",]/g, "");
    query = query.or(`target.ilike.%${sanitized}%,case_number.ilike.%${sanitized}%`);
  }

  const { data: investigations } = await query.limit(100);

  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
  const yesterdayStart = new Date(new Date(todayStart).getTime() - 86400000).toISOString();
  const weekStart = new Date(new Date(todayStart).getTime() - 6 * 86400000).toISOString();

  const invs = (investigations ?? []) as unknown as Investigation[];

  const grouped = {
    today: invs.filter((i) => i.created_at >= todayStart),
    yesterday: invs.filter((i) => i.created_at >= yesterdayStart && i.created_at < todayStart),
    this_week: invs.filter((i) => i.created_at >= weekStart && i.created_at < yesterdayStart),
    archived: invs.filter((i) => i.created_at < weekStart),
  };

  const renderGroup = (label: string, items: Investigation[]) => {
    if (items.length === 0) return null;
    return (
      <div key={label} style={{ marginBottom: "2rem" }}>
        <div
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "0.6875rem",
            textTransform: "uppercase",
            letterSpacing: "0.1em",
            color: "var(--text-tertiary)",
            marginBottom: "0.5rem",
            paddingBottom: "0.4rem",
            borderBottom: "var(--border)",
          }}
        >
          {label}
        </div>
        {items.map((inv) => {
          const tags: string[] = (
            (inv as Investigation & { investigation_tags?: Array<{ tags: { name: string } }> })
              .investigation_tags ?? []
          ).map((t) => t.tags.name);

          return (
            <Link
              key={inv.id}
              href={`/cases/${inv.id}`}
              style={{ textDecoration: "none", color: "inherit", display: "block" }}
            >
              <div className="cases-row">
                <div className="cases-row-main">
                  <span className="case-number-prominent">{inv.case_number}</span>
                  <span className="mono" style={{ fontSize: "0.9375rem", color: "var(--text-primary)" }}>
                    {inv.target}
                  </span>
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.6875rem",
                      color: "var(--text-tertiary)",
                      border: "1px solid var(--bg-border)",
                      padding: "1px 6px",
                      borderRadius: "2px",
                    }}
                  >
                    {inv.target_type}
                  </span>
                  {tags.map((t) => (
                    <span
                      key={t}
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.625rem",
                        padding: "1px 8px",
                        border: "1px solid var(--bg-border)",
                        borderRadius: "100px",
                        color: "var(--text-secondary)",
                      }}
                    >
                      {t}
                    </span>
                  ))}
                </div>
                <div className="cases-row-meta">
                  {inv.final_score !== null && (
                    <span
                      className="mono"
                      style={{ color: scoreColor(inv.final_score), fontWeight: 500 }}
                    >
                      {inv.final_score}/100
                    </span>
                  )}
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.6875rem",
                      color: inv.status === "COMPLETED" ? "var(--accent-confirmed)" : inv.status === "FAILED" ? "var(--accent-severe)" : "var(--accent-open)",
                    }}
                  >
                    {inv.status}
                  </span>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-tertiary)" }}>
                    {new Date(inv.created_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </Link>
          );
        })}
      </div>
    );
  };

  return (
    <>
      <style>{`
        .cases-page { padding: 2rem 2.5rem; max-width: 1000px; }

        .cases-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 2rem;
          padding-bottom: 1.5rem;
          border-bottom: var(--border);
        }

        .cases-title {
          font-family: var(--font-display);
          font-size: 1.5rem;
          font-weight: 500;
          color: var(--text-primary);
        }

        .cases-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 10px 14px;
          border: var(--border);
          border-radius: var(--radius-sm);
          margin-bottom: 4px;
          background: var(--bg-surface);
          transition: background 0.1s, border-color 0.1s;
          cursor: pointer;
          gap: 1rem;
        }

        .cases-row:hover {
          background: var(--bg-surface-2);
          border-color: var(--text-tertiary);
        }

        .cases-row-main {
          display: flex;
          align-items: center;
          gap: 10px;
          min-width: 0;
          flex: 1;
          flex-wrap: wrap;
        }

        .cases-row-meta {
          display: flex;
          align-items: center;
          gap: 12px;
          flex-shrink: 0;
        }
      `}</style>

      <div className="cases-page">
        <div className="cases-header">
          <h1 className="cases-title">Case Files</h1>
          
          <form action="/cases" method="GET" style={{ display: "flex", gap: "8px", maxWidth: "360px", width: "100%" }}>
            <input
              type="text"
              name="q"
              defaultValue={q}
              placeholder="Search target, case #..."
              className="input input-mono"
              style={{ flex: 1, height: "36px", padding: "0 12px", fontSize: "0.875rem" }}
            />
            <button type="submit" className="btn btn-secondary" style={{ height: "36px", padding: "0 14px" }}>
              Search
            </button>
          </form>

          <Link href="/new" className="btn btn-primary" id="new-case-btn">
            + Open Case
          </Link>
        </div>

        {invs.length === 0 ? (
          <div
            style={{
              textAlign: "center",
              padding: "3rem",
              color: "var(--text-secondary)",
            }}
          >
            <p style={{ marginBottom: "1rem" }}>
              {q ? `No investigations found matching "${q}"` : "No investigations yet."}
            </p>
            {q ? (
              <Link href="/cases" className="btn btn-secondary">
                Clear Search
              </Link>
            ) : (
              <Link href="/new" className="btn btn-secondary">
                Open your first case
              </Link>
            )}
          </div>
        ) : (
          <>
            {renderGroup("Today", grouped.today)}
            {renderGroup("Yesterday", grouped.yesterday)}
            {renderGroup("This Week", grouped.this_week)}
            {renderGroup("Archived", grouped.archived)}
          </>
        )}
      </div>
    </>
  );
}
