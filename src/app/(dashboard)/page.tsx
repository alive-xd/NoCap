import { createClient } from "@/lib/supabase/server";
import Link from "next/link";
import type { Investigation } from "@/lib/pipeline/types";

function scoreColor(score: number | null): string {
  if (score === null) return "var(--text-tertiary)";
  if (score >= 75) return "var(--severity-critical)";
  if (score >= 50) return "var(--severity-high)";
  if (score >= 25) return "var(--severity-medium)";
  return "var(--severity-low)";
}

function statusIcon(status: string): string {
  switch (status) {
    case "COMPLETED": return "✓";
    case "FAILED": return "✗";
    case "FETCHING_ARTIFACTS":
    case "EXTRACTING_EVIDENCE":
    case "RUNNING_ANALYZERS":
    case "SCORING": return "◌";
    default: return "○";
  }
}

function formatRelativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return new Date(dateStr).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

function InvestigationRow({ inv }: { inv: Investigation }) {
  return (
    <Link href={`/cases/${inv.id}`} style={{ textDecoration: "none", color: "inherit", display: "block" }}>
      <div className="inv-row">
        <div className="inv-row-left">
          <span className="case-number">{inv.case_number}</span>
          <span className="inv-target">{inv.target}</span>
          <span className="inv-type">{inv.target_type}</span>
        </div>
        <div className="inv-row-right">
          {inv.final_score !== null && (
            <span className="inv-score mono" style={{ color: scoreColor(inv.final_score) }}>
              {inv.final_score}
            </span>
          )}
          <span className={`inv-status-icon ${inv.status === "COMPLETED" ? "source-ok" : inv.status === "FAILED" ? "source-fail" : "source-warn"}`}>
            {statusIcon(inv.status)}
          </span>
          <span className="inv-time text-tertiary">{formatRelativeTime(inv.created_at)}</span>
        </div>
      </div>
    </Link>
  );
}

export default async function DashboardPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return null;

  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
  const yesterdayStart = new Date(new Date(todayStart).getTime() - 86400000).toISOString();
  const weekStart = new Date(new Date(todayStart).getTime() - 6 * 86400000).toISOString();

  // Operational counts — what an analyst needs for today's workload
  const [todayCount, pendingCount, failedCount, recentInvs, watchlistItems, recentFindings] =
    await Promise.all([
      supabase
        .from("investigations")
        .select("*", { count: "exact", head: true })
        .eq("user_id", user.id)
        .gte("created_at", todayStart),
      supabase
        .from("investigations")
        .select("*", { count: "exact", head: true })
        .eq("user_id", user.id)
        .in("status", ["CREATED", "FETCHING_ARTIFACTS", "EXTRACTING_EVIDENCE", "RUNNING_ANALYZERS", "SCORING"]),
      supabase
        .from("investigations")
        .select("*", { count: "exact", head: true })
        .eq("user_id", user.id)
        .eq("status", "FAILED")
        .gte("created_at", todayStart),
      supabase
        .from("investigations")
        .select("id, case_number, target, target_type, status, final_score, created_at")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false })
        .limit(30),
      supabase
        .from("watchlist")
        .select("id, target, module, created_at")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false })
        .limit(5),
      supabase
        .from("findings")
        .select(`
          id, claim, severity, confidence_score, created_at,
          investigations!inner(id, case_number, target, user_id)
        `)
        .eq("investigations.user_id", user.id)
        .in("severity", ["CRITICAL", "HIGH"])
        .order("created_at", { ascending: false })
        .limit(5),
    ]);

  const investigations = (recentInvs.data ?? []) as Investigation[];

  const grouped = {
    today: investigations.filter((i) => i.created_at >= todayStart),
    yesterday: investigations.filter((i) => i.created_at >= yesterdayStart && i.created_at < todayStart),
    this_week: investigations.filter((i) => i.created_at >= weekStart && i.created_at < yesterdayStart),
    archived: investigations.filter((i) => i.created_at < weekStart),
  };

  return (
    <>
      <style>{`
        .desk-page {
          padding: 2rem 2.5rem;
          max-width: 1100px;
        }

        .desk-header {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          margin-bottom: 2rem;
          padding-bottom: 1.5rem;
          border-bottom: var(--border);
        }

        .desk-title {
          font-family: var(--font-display);
          font-size: 1.5rem;
          font-weight: 500;
          color: var(--text-primary);
          margin-bottom: 0.25rem;
        }

        .desk-subtitle {
          font-size: 0.875rem;
          color: var(--text-secondary);
        }

        .desk-action {
          flex-shrink: 0;
        }

        .ops-strip {
          display: flex;
          gap: 1.5rem;
          margin-bottom: 2rem;
          padding: 1rem 1.5rem;
          background: var(--bg-surface);
          border: var(--border);
          border-radius: var(--radius-md);
        }

        .ops-item {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }

        .ops-divider {
          width: 1px;
          background: var(--bg-border);
          align-self: stretch;
        }

        .ops-value {
          font-family: var(--font-mono);
          font-size: 1.5rem;
          font-weight: 500;
          line-height: 1;
          color: var(--text-primary);
        }

        .ops-value.pending { color: var(--accent-open); }
        .ops-value.failed { color: var(--accent-severe); }

        .ops-label {
          font-size: 0.75rem;
          color: var(--text-tertiary);
          text-transform: uppercase;
          letter-spacing: 0.06em;
          font-family: var(--font-mono);
        }

        .desk-columns {
          display: grid;
          grid-template-columns: 1fr 320px;
          gap: 2rem;
          align-items: start;
        }

        .case-group {
          margin-bottom: 1.5rem;
        }

        .case-group-label {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--text-tertiary);
          text-transform: uppercase;
          letter-spacing: 0.1em;
          margin-bottom: 0.5rem;
          padding-bottom: 0.4rem;
          border-bottom: var(--border);
        }

        .inv-row {
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
        }

        .inv-row:hover {
          background: var(--bg-surface-2);
          border-color: var(--text-tertiary);
        }

        .inv-row-left {
          display: flex;
          align-items: center;
          gap: 10px;
          min-width: 0;
          flex: 1;
        }

        .inv-target {
          font-family: var(--font-mono);
          font-size: 0.875rem;
          color: var(--text-primary);
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .inv-type {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--text-tertiary);
          flex-shrink: 0;
          border: 1px solid var(--bg-border);
          padding: 1px 6px;
          border-radius: 2px;
        }

        .inv-row-right {
          display: flex;
          align-items: center;
          gap: 12px;
          flex-shrink: 0;
        }

        .inv-score {
          font-size: 0.9375rem;
          font-weight: 500;
          min-width: 28px;
          text-align: right;
        }

        .inv-status-icon {
          font-size: 0.875rem;
          width: 16px;
          text-align: center;
        }

        .inv-time {
          font-size: 0.75rem;
          min-width: 56px;
          text-align: right;
        }

        .sidebar-widget {
          background: var(--bg-surface);
          border: var(--border);
          border-radius: var(--radius-md);
          margin-bottom: 1.5rem;
          overflow: hidden;
        }

        .widget-header {
          padding: 12px 16px;
          border-bottom: var(--border);
          display: flex;
          align-items: center;
          justify-content: space-between;
        }

        .widget-title {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          color: var(--text-secondary);
        }

        .widget-body {
          padding: 0;
        }

        .widget-row {
          padding: 10px 16px;
          border-bottom: var(--border);
          font-size: 0.875rem;
        }

        .widget-row:last-child { border-bottom: none; }

        .widget-empty {
          padding: 1.5rem 16px;
          color: var(--text-tertiary);
          font-size: 0.8125rem;
          text-align: center;
        }

        .finding-row-claim {
          color: var(--text-primary);
          margin-bottom: 2px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .finding-row-meta {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--text-tertiary);
        }

        .watchlist-target {
          font-family: var(--font-mono);
          font-size: 0.8125rem;
          color: var(--text-primary);
        }

        .empty-cases {
          padding: 3rem 1rem;
          text-align: center;
          color: var(--text-secondary);
        }

        .empty-cases p {
          margin-bottom: 1rem;
          font-size: 0.9375rem;
        }
      `}</style>

      <div className="desk-page">
        <div className="desk-header">
          <div>
            <h1 className="desk-title">Investigator&apos;s Desk</h1>
            <p className="desk-subtitle">
              {new Date().toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" })}
            </p>
          </div>
          <div className="desk-action">
            <Link href="/new" className="btn btn-primary" id="new-investigation-btn">
              + New Investigation
            </Link>
          </div>
        </div>

        {/* Operational counts */}
        <div className="ops-strip">
          <div className="ops-item">
            <span className="ops-value">{todayCount.count ?? 0}</span>
            <span className="ops-label">Today</span>
          </div>
          <div className="ops-divider" />
          <div className="ops-item">
            <span className={`ops-value ${(pendingCount.count ?? 0) > 0 ? "pending" : ""}`}>
              {pendingCount.count ?? 0}
            </span>
            <span className="ops-label">Pending</span>
          </div>
          <div className="ops-divider" />
          <div className="ops-item">
            <span className={`ops-value ${(failedCount.count ?? 0) > 0 ? "failed" : ""}`}>
              {failedCount.count ?? 0}
            </span>
            <span className="ops-label">Failed (Today)</span>
          </div>
        </div>

        <div className="desk-columns">
          {/* Left: Recent Cases */}
          <div>
            <div
              style={{
                fontFamily: "var(--font-display)",
                fontSize: "1rem",
                fontWeight: 500,
                marginBottom: "1.25rem",
                color: "var(--text-primary)",
              }}
            >
              Case Files
            </div>

            {investigations.length === 0 ? (
              <div className="empty-cases panel">
                <p>No investigations yet.</p>
                <Link href="/new" className="btn btn-secondary">
                  Open your first case
                </Link>
              </div>
            ) : (
              <>
                {grouped.today.length > 0 && (
                  <div className="case-group">
                    <div className="case-group-label">Today</div>
                    {grouped.today.map((inv) => (
                      <InvestigationRow key={inv.id} inv={inv} />
                    ))}
                  </div>
                )}
                {grouped.yesterday.length > 0 && (
                  <div className="case-group">
                    <div className="case-group-label">Yesterday</div>
                    {grouped.yesterday.map((inv) => (
                      <InvestigationRow key={inv.id} inv={inv} />
                    ))}
                  </div>
                )}
                {grouped.this_week.length > 0 && (
                  <div className="case-group">
                    <div className="case-group-label">This Week</div>
                    {grouped.this_week.map((inv) => (
                      <InvestigationRow key={inv.id} inv={inv} />
                    ))}
                  </div>
                )}
                {grouped.archived.length > 0 && (
                  <div className="case-group">
                    <div className="case-group-label">Archived</div>
                    {grouped.archived.slice(0, 5).map((inv) => (
                      <InvestigationRow key={inv.id} inv={inv} />
                    ))}
                    {grouped.archived.length > 5 && (
                      <Link
                        href="/cases"
                        style={{ display: "block", textAlign: "center", padding: "8px", fontSize: "0.8125rem", color: "var(--text-tertiary)" }}
                      >
                        View all {grouped.archived.length} archived →
                      </Link>
                    )}
                  </div>
                )}
              </>
            )}
          </div>

          {/* Right: Sidebar widgets */}
          <div>
            {/* CVE Watchlist */}
            <div className="sidebar-widget">
              <div className="widget-header">
                <span className="widget-title">CVE Watchlist</span>
                <Link href="/watchlist" style={{ fontSize: "0.75rem", color: "var(--text-tertiary)", textDecoration: "none" }}>
                  Manage →
                </Link>
              </div>
              <div className="widget-body">
                {(watchlistItems.data ?? []).length === 0 ? (
                  <div className="widget-empty">No watchlist entries</div>
                ) : (
                  watchlistItems.data?.map((item: Record<string, unknown>) => (
                    <div key={String(item.id)} className="widget-row">
                      <div className="watchlist-target">{String(item.target ?? "")}</div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Recent High/Critical Findings */}
            <div className="sidebar-widget">
              <div className="widget-header">
                <span className="widget-title">Recent Findings</span>
                <span style={{ fontSize: "0.75rem", color: "var(--text-tertiary)" }}>
                  CRITICAL / HIGH
                </span>
              </div>
              <div className="widget-body">
                {(recentFindings.data ?? []).length === 0 ? (
                  <div className="widget-empty">No high-severity findings</div>
                ) : (
                  recentFindings.data?.map((finding: Record<string, unknown>) => {
                    const inv = ((finding as unknown) as { investigations: { id: string; case_number: string; target: string } }).investigations;
                    return (
                      <Link
                        key={String(finding.id)}
                        href={`/cases/${inv?.id ?? ""}`}
                        style={{ textDecoration: "none", color: "inherit", display: "block" }}
                      >
                        <div className="widget-row" style={{ cursor: "pointer" }}>
                          <div className="finding-row-claim">{String(finding.claim ?? "")}</div>
                          <div className="finding-row-meta">
                            <span
                              className={`severity-badge severity-${String(finding.severity ?? "")}`}
                              style={{ fontSize: "0.5625rem", padding: "1px 5px" }}
                            >
                              {String(finding.severity ?? "")}
                            </span>
                            <span style={{ marginLeft: "6px" }}>{inv?.case_number}</span>
                          </div>
                        </div>
                      </Link>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
