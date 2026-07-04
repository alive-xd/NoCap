"use client";

import { useState } from "react";
import { createClient } from "@/lib/supabase/client";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [magicSent, setMagicSent] = useState(false);
  const router = useRouter();
  const supabase = createClient();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === "signup") {
        const { error } = await supabase.auth.signUp({ email, password });
        if (error) throw error;
        setMagicSent(true);
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        router.push("/");
        router.refresh();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  if (magicSent) {
    return (
      <div className="login-container">
        <div className="login-card">
          <div className="login-stamp-icon">✉</div>
          <h1 className="login-title">Check your inbox</h1>
          <p className="login-subtitle">
            A confirmation link has been sent to <span className="mono">{email}</span>.
            Open it to activate your account.
          </p>
        </div>
      </div>
    );
  }

  return (
    <>
      <style>{`
        .login-container {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          background: var(--bg-base);
          padding: 2rem;
        }

        .login-card {
          width: 100%;
          max-width: 400px;
          background: var(--bg-surface);
          border: var(--border);
          border-radius: var(--radius-md);
          padding: 2.5rem 2rem;
        }

        .login-header {
          margin-bottom: 2rem;
        }

        .login-wordmark {
          font-family: var(--font-display);
          font-size: 1.75rem;
          font-weight: 600;
          color: var(--text-primary);
          letter-spacing: -0.02em;
          margin-bottom: 0.25rem;
        }

        .login-wordmark span {
          color: var(--accent-open);
        }

        .login-tagline {
          font-size: 0.8125rem;
          color: var(--text-tertiary);
          font-family: var(--font-mono);
          letter-spacing: 0.04em;
          text-transform: uppercase;
        }

        .login-title {
          font-family: var(--font-display);
          font-size: 1.125rem;
          font-weight: 500;
          color: var(--text-primary);
          margin-bottom: 0.5rem;
        }

        .login-subtitle {
          font-size: 0.875rem;
          color: var(--text-secondary);
          line-height: 1.6;
        }

        .login-form {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          margin-top: 1.5rem;
        }

        .login-field label {
          display: block;
          font-size: 0.8125rem;
          color: var(--text-secondary);
          margin-bottom: 6px;
          font-weight: 500;
        }

        .login-submit {
          width: 100%;
          justify-content: center;
          margin-top: 0.5rem;
        }

        .login-error {
          background: color-mix(in srgb, var(--accent-severe) 10%, transparent);
          border: 1px solid var(--accent-severe);
          border-radius: var(--radius-sm);
          padding: 10px 14px;
          font-size: 0.875rem;
          color: var(--accent-severe);
        }

        .login-divider {
          border: none;
          border-top: var(--border);
          margin: 1.5rem 0;
        }

        .login-toggle {
          text-align: center;
          font-size: 0.875rem;
          color: var(--text-secondary);
        }

        .login-toggle button {
          background: none;
          border: none;
          color: var(--accent-open);
          cursor: pointer;
          font-size: 0.875rem;
          font-family: var(--font-body);
          text-decoration: underline;
          padding: 0;
        }

        .login-stamp-icon {
          font-size: 2rem;
          margin-bottom: 1rem;
          color: var(--accent-confirmed);
        }

        .login-footer {
          margin-top: 2rem;
          padding-top: 1.5rem;
          border-top: var(--border);
          font-size: 0.75rem;
          color: var(--text-tertiary);
          text-align: center;
          line-height: 1.8;
        }

        .login-footer .mono {
          font-size: 0.6875rem;
          color: var(--text-tertiary);
        }
      `}</style>

      <div className="login-container">
        <div className="login-card">
          <div className="login-header">
            <div className="login-wordmark">
              No<span>Cap</span>
            </div>
            <div className="login-tagline">Threat Intelligence Platform</div>
          </div>

          <h1 className="login-title">
            {mode === "signin" ? "Open a session" : "Create account"}
          </h1>
          <p className="login-subtitle">
            {mode === "signin"
              ? "Sign in to access your case files and investigation history."
              : "Create an analyst account to start investigating indicators."}
          </p>

          <form className="login-form" onSubmit={handleSubmit}>
            {error && <div className="login-error">{error}</div>}

            <div className="login-field">
              <label htmlFor="email">Email address</label>
              <input
                id="email"
                type="email"
                className="input"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@example.com"
                required
                autoComplete="email"
              />
            </div>

            <div className="login-field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                className="input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                autoComplete={mode === "signin" ? "current-password" : "new-password"}
                minLength={8}
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary login-submit"
              disabled={loading}
            >
              {loading
                ? "Working..."
                : mode === "signin"
                ? "Open Case Files"
                : "Create Account"}
            </button>
          </form>

          <hr className="login-divider" />

          <div className="login-toggle">
            {mode === "signin" ? (
              <>
                New analyst?{" "}
                <button onClick={() => setMode("signup")}>Create account</button>
              </>
            ) : (
              <>
                Already registered?{" "}
                <button onClick={() => setMode("signin")}>Sign in</button>
              </>
            )}
          </div>

          <div className="login-footer">
            <span className="mono">NoCap v1.0 — Evidence-backed threat intelligence</span>
          </div>
        </div>
      </div>
    </>
  );
}
