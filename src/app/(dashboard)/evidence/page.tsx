"use client";

import { useEffect, useState } from "react";

const SOURCES = ["virustotal", "abuseipdb", "whois", "ipasn", "domainstring", "crtsh", "email_headers", "homograph", "http_fingerprint", "github_search"];
const PARSERS = ["VirusTotalParser", "AbuseIPDBParser", "WHOISParser", "DomainStringParser", "ASNLookupParser", "SubdomainParser", "EmailHeaderParser", "HomographParser", "HTTPFingerprintParser", "GitHubExposureParser"];

interface EvidenceItem {
  id: string;
  fact_type: string;
  fact_value: unknown;
  parser_name: string;
  parser_version: string;
  created_at: string;
  artifacts: {
    source: string;
    investigation_id: string;
    investigations: {
      case_number: string;
      target: string;
    };
  };
}

export default function EvidenceExplorerPage() {
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [sourceFilter, setSourceFilter] = useState("");
  const [parserFilter, setParserFilter] = useState("");
  const [page, setPage] = useState(0);

  const limit = 50;

  useEffect(() => {
    const params = new URLSearchParams({
      limit: limit.toString(),
      offset: (page * limit).toString(),
    });
    if (sourceFilter) params.set("source", sourceFilter);
    if (parserFilter) params.set("parser", parserFilter);

    setLoading(true);
    fetch(`/api/evidence?${params}`)
      .then((r) => r.json())
      .then((data: { evidence: EvidenceItem[]; total: number }) => {
        setEvidence(data.evidence);
        setTotal(data.total);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [sourceFilter, parserFilter, page]);

  return (
    <>
      <style>{`
        .explorer-page { padding: 2rem 2.5rem; max-width: 1100px; }

        .explorer-header {
          margin-bottom: 1.5rem;
          padding-bottom: 1.25rem;
          border-bottom: var(--border);
        }

        .explorer-title {
          font-family: var(--font-display);
          font-size: 1.5rem;
          font-weight: 500;
          color: var(--text-primary);
          margin-bottom: 0.25rem;
        }

        .explorer-subtitle {
          font-size: 0.875rem;
          color: var(--text-secondary);
        }

        .explorer-filters {
          display: flex;
          gap: 1rem;
          margin-bottom: 1.25rem;
          flex-wrap: wrap;
        }

        .filter-select {
          background: var(--bg-surface);
          border: var(--border);
          border-radius: var(--radius-md);
          color: var(--text-primary);
          font-family: var(--font-body);
          font-size: 0.875rem;
          padding: 8px 12px;
          cursor: pointer;
          outline: none;
          transition: border-color 0.12s;
          min-width: 160px;
        }

        .filter-select:focus { border-color: var(--accent-open); }

        .evidence-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.875rem;
        }

        .evidence-table th {
          text-align: left;
          padding: 8px 12px;
          font-family: var(--font-mono);
          font-size: 0.625rem;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          color: var(--text-tertiary);
          border-bottom: var(--border);
          font-weight: 400;
        }

        .evidence-table td {
          padding: 10px 12px;
          border-bottom: 1px solid var(--bg-border);
          vertical-align: top;
        }

        .evidence-table tr:hover td { background: var(--bg-surface-2); }

        .ev-fact-type {
          font-family: var(--font-mono);
          font-size: 0.8125rem;
          color: var(--accent-open);
        }

        .ev-fact-value {
          font-family: var(--font-mono);
          font-size: 0.8125rem;
          color: var(--text-primary);
          max-width: 320px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .ev-parser {
          font-family: var(--font-mono);
          font-size: 0.75rem;
          color: var(--text-secondary);
        }

        .ev-source {
          font-family: var(--font-mono);
          font-size: 0.75rem;
          color: var(--text-tertiary);
          border: 1px solid var(--bg-border);
          padding: 1px 6px;
          border-radius: 2px;
        }

        .ev-case {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--text-tertiary);
        }

        .pagination {
          display: flex;
          align-items: center;
          gap: 1rem;
          margin-top: 1.5rem;
          font-size: 0.875rem;
          color: var(--text-secondary);
        }

        .explorer-stats {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--text-tertiary);
          margin-bottom: 1rem;
        }
      `}</style>

      <div className="explorer-page">
        <div className="explorer-header">
          <h1 className="explorer-title">Evidence Explorer</h1>
          <p className="explorer-subtitle">
            Every atomic fact extracted from raw API responses — the raw material for every Finding in the platform.
          </p>
        </div>

        <div className="explorer-filters">
          <select
            className="filter-select"
            value={sourceFilter}
            onChange={(e) => { setSourceFilter(e.target.value); setPage(0); }}
            id="source-filter-select"
            aria-label="Filter by source"
          >
            <option value="">All Sources</option>
            {SOURCES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          <select
            className="filter-select"
            value={parserFilter}
            onChange={(e) => { setParserFilter(e.target.value); setPage(0); }}
            id="parser-filter-select"
            aria-label="Filter by parser"
          >
            <option value="">All Parsers</option>
            {PARSERS.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>

        <div className="explorer-stats">
          {loading ? "Loading…" : `${total} evidence record${total !== 1 ? "s" : ""} — showing ${page * limit + 1}–${Math.min((page + 1) * limit, total)}`}
        </div>

        {loading ? (
          <div className="redacted-block" style={{ height: "300px", borderRadius: "var(--radius-sm)" }} />
        ) : (
          <table className="evidence-table" aria-label="Evidence records">
            <thead>
              <tr>
                <th>Fact Type</th>
                <th>Fact Value</th>
                <th>Parser</th>
                <th>Source</th>
                <th>Case</th>
                <th>Extracted</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((ev) => (
                <tr key={ev.id}>
                  <td><span className="ev-fact-type">{ev.fact_type}</span></td>
                  <td>
                    <span className="ev-fact-value" title={JSON.stringify(ev.fact_value)}>
                      {typeof ev.fact_value === "object"
                        ? JSON.stringify(ev.fact_value)
                        : String(ev.fact_value)}
                    </span>
                  </td>
                  <td>
                    <span className="ev-parser">
                      {ev.parser_name} <span style={{ opacity: 0.6 }}>v{ev.parser_version}</span>
                    </span>
                  </td>
                  <td><span className="ev-source">{ev.artifacts?.source}</span></td>
                  <td>
                    <span className="ev-case">{ev.artifacts?.investigations?.case_number}</span>
                  </td>
                  <td>
                    <span style={{ fontSize: "0.6875rem", color: "var(--text-tertiary)", fontFamily: "var(--font-mono)" }}>
                      {new Date(ev.created_at).toLocaleTimeString()}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {total > limit && (
          <div className="pagination">
            <button
              className="btn btn-secondary"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              id="ev-prev-btn"
              style={{ padding: "6px 14px" }}
            >
              ← Previous
            </button>
            <span>Page {page + 1} of {Math.ceil(total / limit)}</span>
            <button
              className="btn btn-secondary"
              onClick={() => setPage((p) => p + 1)}
              disabled={(page + 1) * limit >= total}
              id="ev-next-btn"
              style={{ padding: "6px 14px" }}
            >
              Next →
            </button>
          </div>
        )}
      </div>
    </>
  );
}
