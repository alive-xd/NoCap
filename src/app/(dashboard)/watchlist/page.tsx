"use client";

import { useEffect, useState } from "react";

interface WatchlistItem {
  id: string;
  target: string;
  module: string;
  created_at: string;
}

export default function WatchlistPage() {
  const [items, setItems] = useState<WatchlistItem[]>([]);
  const [newTarget, setNewTarget] = useState("");
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);

  const fetchItems = async () => {
    const res = await fetch("/api/watchlist");
    if (res.ok) {
      const data = await res.json() as WatchlistItem[];
      setItems(data);
    }
    setLoading(false);
  };

  useEffect(() => { fetchItems(); }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim()) return;
    setAdding(true);
    await fetch("/api/watchlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: newTarget.trim(), module: "cve_watch" }),
    });
    setNewTarget("");
    setAdding(false);
    fetchItems();
  };

  const handleRemove = async (id: string) => {
    await fetch("/api/watchlist", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    fetchItems();
  };

  return (
    <>
      <style>{`
        .watchlist-page { padding: 2rem 2.5rem; max-width: 720px; }

        .watchlist-header {
          margin-bottom: 2rem;
          padding-bottom: 1.5rem;
          border-bottom: var(--border);
        }

        .watchlist-title {
          font-family: var(--font-display);
          font-size: 1.5rem;
          font-weight: 500;
          color: var(--text-primary);
          margin-bottom: 0.25rem;
        }

        .watchlist-subtitle {
          font-size: 0.875rem;
          color: var(--text-secondary);
        }

        .watchlist-add-form {
          display: flex;
          gap: 0.75rem;
          margin-bottom: 2rem;
        }

        .watchlist-items { display: flex; flex-direction: column; gap: 6px; }

        .watchlist-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 12px 16px;
          background: var(--bg-surface);
          border: var(--border);
          border-radius: var(--radius-sm);
        }

        .watchlist-item-left {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .watchlist-item-target {
          font-family: var(--font-mono);
          font-size: 0.9375rem;
          color: var(--text-primary);
        }

        .watchlist-item-module {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--text-tertiary);
          border: 1px solid var(--bg-border);
          padding: 1px 6px;
          border-radius: 2px;
        }

        .watchlist-item-date {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--text-tertiary);
        }

        .watchlist-empty {
          padding: 2rem;
          text-align: center;
          color: var(--text-secondary);
          background: var(--bg-surface);
          border: var(--border);
          border-radius: var(--radius-md);
        }

        .watchlist-explainer {
          padding: 1rem 1.25rem;
          background: var(--bg-surface);
          border: var(--border);
          border-left: 3px solid var(--accent-open);
          border-radius: var(--radius-sm);
          margin-bottom: 2rem;
          font-size: 0.875rem;
          color: var(--text-secondary);
          line-height: 1.6;
        }
      `}</style>

      <div className="watchlist-page">
        <div className="watchlist-header">
          <h1 className="watchlist-title">CVE Watchlist</h1>
          <p className="watchlist-subtitle">
            Track CVE identifiers, product names, or technology keywords. The CVE Watch investigation type will scan for active vulnerabilities.
          </p>
        </div>

        <div className="watchlist-explainer">
          <strong style={{ color: "var(--text-primary)" }}>How it works:</strong> Add a CVE ID, product name, or vendor to your watchlist.
          The platform will trigger a CVE Watch investigation against NVD, Exploit-DB, and CISA KEV to flag newly disclosed or actively exploited vulnerabilities matching your entries.
          Prioritization uses the composite CVSS + exploit + recency formula from CVEPriorityAnalyzer.
        </div>

        <form className="watchlist-add-form" onSubmit={handleAdd}>
          <input
            className="input input-mono"
            value={newTarget}
            onChange={(e) => setNewTarget(e.target.value)}
            placeholder="CVE-2024-12345 or product name…"
            id="watchlist-add-input"
            style={{ flex: 1 }}
            required
          />
          <button
            type="submit"
            className="btn btn-primary"
            disabled={adding}
            id="watchlist-add-btn"
          >
            {adding ? "Adding…" : "Add to Watchlist"}
          </button>
        </form>

        {loading ? (
          <div className="redacted-block" style={{ height: "160px", borderRadius: "var(--radius-sm)" }} />
        ) : items.length === 0 ? (
          <div className="watchlist-empty">
            No watchlist entries. Add a CVE or product above.
          </div>
        ) : (
          <div className="watchlist-items" aria-label="Watchlist entries">
            {items.map((item) => (
              <div key={item.id} className="watchlist-item">
                <div className="watchlist-item-left">
                  <span className="watchlist-item-target">{item.target}</span>
                  <span className="watchlist-item-module">{item.module.replace(/_/g, " ").toUpperCase()}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <span className="watchlist-item-date">
                    Added {new Date(item.created_at).toLocaleDateString()}
                  </span>
                  <button
                    className="btn btn-danger"
                    onClick={() => handleRemove(item.id)}
                    style={{ padding: "4px 10px", fontSize: "0.8125rem" }}
                    id={`watchlist-remove-${item.id}`}
                    aria-label={`Remove ${item.target} from watchlist`}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
