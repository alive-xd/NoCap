"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { detectIOCType } from "@/lib/investigation/iocDetector";

type InvestigationType = "ioc" | "phishing" | "attack_surface";

const TYPE_LABELS: Record<InvestigationType, { label: string; description: string; placeholder: string }> = {
  ioc: {
    label: "IOC Investigation",
    description: "Investigate an IP address, domain, URL, or file hash through VirusTotal, AbuseIPDB, WHOIS, and ASN reputation.",
    placeholder: "e.g. 8.8.8.8, malware.example.com, https://..., d41d8cd98f00b204e9800998ecf8427e",
  },
  phishing: {
    label: "Phishing Investigation",
    description: "Analyze a URL or paste raw email headers to detect brand impersonation, SPF/DKIM/DMARC failures, and suspicious routing.",
    placeholder: "https://suspicious-domain.com or paste raw email headers",
  },
  attack_surface: {
    label: "Attack Surface Investigation",
    description: "Enumerate subdomains via CT logs, fingerprint the technology stack, and check for exposed secrets on GitHub.",
    placeholder: "example.com",
  },
};

export default function NewInvestigationPage() {
  const router = useRouter();
  const [invType, setInvType] = useState<InvestigationType>("ioc");
  const [target, setTarget] = useState("");
  const [rawHeaders, setRawHeaders] = useState("");
  const [batchMode, setBatchMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detectedType, setDetectedType] = useState<string>("");

  const handleTargetChange = (val: string) => {
    setTarget(val);
    if (invType === "ioc" && val.trim() && !batchMode) {
      setDetectedType(detectIOCType(val.trim()));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const targets = batchMode
      ? target.split("\n").map((t) => t.trim()).filter(Boolean)
      : [target.trim()];

    if (targets.length === 0) {
      setError("Please enter at least one target.");
      return;
    }

    setLoading(true);

    try {
      if (batchMode) {
        const res = await fetch("/api/investigations/batch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ targets, investigationType: invType }),
        });
        const data = await res.json() as { results: Array<{ id: string }> };
        if (!res.ok) throw new Error((data as { error?: string }).error ?? "Batch failed");
        router.push("/cases");
      } else {
        const body: Record<string, unknown> = {
          target: targets[0],
          investigationType: invType,
        };
        if (invType === "phishing" && rawHeaders) {
          body.rawEmailHeaders = rawHeaders;
        }

        const res = await fetch("/api/investigations", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = await res.json() as { id?: string; error?: string };
        if (!res.ok) throw new Error(data.error ?? "Failed to start investigation");
        router.push(`/cases/${data.id}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  const typeInfo = TYPE_LABELS[invType];

  return (
    <>
      <style>{`
        .new-page {
          padding: 2rem 2.5rem;
          max-width: 720px;
          margin: 0 auto;
        }

        .new-header {
          margin-bottom: 2rem;
          padding-bottom: 1.5rem;
          border-bottom: var(--border);
        }

        .new-title {
          font-family: var(--font-display);
          font-size: 1.5rem;
          font-weight: 500;
          color: var(--text-primary);
          margin-bottom: 0.25rem;
        }

        .new-subtitle {
          font-size: 0.875rem;
          color: var(--text-secondary);
        }

        .type-tabs {
          display: flex;
          gap: 0;
          border: var(--border);
          border-radius: var(--radius-md);
          overflow: hidden;
          margin-bottom: 1.5rem;
        }

        .type-tab {
          flex: 1;
          padding: 10px 12px;
          border: none;
          background: transparent;
          color: var(--text-secondary);
          font-size: 0.8125rem;
          font-family: var(--font-body);
          cursor: pointer;
          border-right: var(--border);
          transition: background 0.12s, color 0.12s;
          text-align: center;
        }

        .type-tab:last-child { border-right: none; }

        .type-tab:hover {
          background: var(--bg-surface-2);
          color: var(--text-primary);
        }

        .type-tab.active {
          background: color-mix(in srgb, var(--accent-open) 10%, var(--bg-surface));
          color: var(--accent-open);
          font-weight: 500;
        }

        .type-description {
          padding: 12px 14px;
          background: var(--bg-surface);
          border: var(--border);
          border-radius: var(--radius-sm);
          font-size: 0.875rem;
          color: var(--text-secondary);
          line-height: 1.6;
          margin-bottom: 1.5rem;
        }

        .form-group {
          margin-bottom: 1.25rem;
        }

        .form-label {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 6px;
          font-size: 0.875rem;
          color: var(--text-secondary);
          font-weight: 500;
        }

        .detected-type {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--accent-open);
          letter-spacing: 0.05em;
        }

        .batch-toggle {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
          font-size: 0.875rem;
          color: var(--text-secondary);
          margin-bottom: 1.25rem;
          user-select: none;
        }

        .batch-toggle input[type="checkbox"] {
          accent-color: var(--accent-open);
          width: 14px;
          height: 14px;
          cursor: pointer;
        }

        .form-error {
          background: color-mix(in srgb, var(--accent-severe) 10%, transparent);
          border: 1px solid var(--accent-severe);
          border-radius: var(--radius-sm);
          padding: 10px 14px;
          font-size: 0.875rem;
          color: var(--accent-severe);
          margin-bottom: 1rem;
        }

        .submit-row {
          display: flex;
          align-items: center;
          gap: 1rem;
          margin-top: 1.5rem;
        }

        .target-input-large {
          font-family: var(--font-mono);
          font-size: 0.9375rem;
        }
      `}</style>

      <div className="new-page">
        <div className="new-header">
          <h1 className="new-title">Open New Case</h1>
          <p className="new-subtitle">
            Submit an indicator or target to begin an investigation pipeline.
          </p>
        </div>

        <div className="type-tabs" role="tablist" aria-label="Investigation type">
          {(Object.keys(TYPE_LABELS) as InvestigationType[]).map((t) => (
            <button
              key={t}
              role="tab"
              aria-selected={invType === t}
              className={`type-tab ${invType === t ? "active" : ""}`}
              onClick={() => { setInvType(t); setDetectedType(""); }}
              id={`tab-${t}`}
            >
              {TYPE_LABELS[t].label}
            </button>
          ))}
        </div>

        <div className="type-description">{typeInfo.description}</div>

        <form onSubmit={handleSubmit}>
          {error && <div className="form-error">{error}</div>}

          {invType === "ioc" && (
            <label className="batch-toggle">
              <input
                type="checkbox"
                id="batch-mode-toggle"
                checked={batchMode}
                onChange={(e) => setBatchMode(e.target.checked)}
              />
              Batch mode — paste multiple IOCs (one per line, max 20)
            </label>
          )}

          <div className="form-group">
            <div className="form-label">
              <label htmlFor="target-input">
                {batchMode ? "IOC List" : "Target"}
              </label>
              {detectedType && !batchMode && (
                <span className="detected-type">Detected: {detectedType}</span>
              )}
            </div>
            {batchMode ? (
              <textarea
                id="target-input"
                className="input input-mono"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={"8.8.8.8\n1.1.1.1\nmalware.example.com"}
                rows={8}
                required
              />
            ) : (
              <input
                id="target-input"
                type="text"
                className="input target-input-large"
                value={target}
                onChange={(e) => handleTargetChange(e.target.value)}
                placeholder={typeInfo.placeholder}
                required
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="off"
              />
            )}
          </div>

          {invType === "phishing" && !batchMode && (
            <div className="form-group">
              <div className="form-label">
                <label htmlFor="email-headers">
                  Raw Email Headers{" "}
                  <span style={{ color: "var(--text-tertiary)", fontWeight: 400 }}>
                    (optional — paste full header block for SPF/DKIM/DMARC analysis)
                  </span>
                </label>
              </div>
              <textarea
                id="email-headers"
                className="input input-mono"
                value={rawHeaders}
                onChange={(e) => setRawHeaders(e.target.value)}
                placeholder={"Received: from mail.example.com ...\nFrom: ...\nAuthentication-Results: ..."}
                rows={6}
              />
            </div>
          )}

          <div className="submit-row">
            <button
              type="submit"
              className="btn btn-primary"
              id="open-case-submit-btn"
              disabled={loading}
            >
              {loading ? "Opening case..." : batchMode ? `Run ${target.split("\n").filter(Boolean).length} Investigations` : "Open Case"}
            </button>
            {loading && (
              <span style={{ fontSize: "0.8125rem", color: "var(--text-tertiary)" }}>
                Pipeline starting — you&apos;ll be redirected when ready.
              </span>
            )}
          </div>
        </form>
      </div>
    </>
  );
}
