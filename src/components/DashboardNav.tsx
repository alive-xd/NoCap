"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";

const NAV_ITEMS = [
  { href: "/", label: "Investigator's Desk", icon: "⬡" },
  { href: "/new", label: "Open Case", icon: "+" },
  { href: "/cases", label: "Case Files", icon: "▤" },
  { href: "/evidence", label: "Evidence Explorer", icon: "◈" },
  { href: "/analyzers", label: "Analyzer Library", icon: "⊞" },
  { href: "/watchlist", label: "CVE Watchlist", icon: "◉" },
];

export default function DashboardNav({ userEmail }: { userEmail: string }) {
  const pathname = usePathname();
  const router = useRouter();
  const supabase = createClient();

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    router.push("/login");
    router.refresh();
  };

  return (
    <>
      <style>{`
        .nav-sidebar {
          position: fixed;
          top: 0;
          left: 0;
          width: 220px;
          height: 100vh;
          background: var(--bg-surface);
          border-right: var(--border);
          display: flex;
          flex-direction: column;
          z-index: 100;
        }

        .nav-wordmark {
          padding: 1.5rem 1.25rem 1rem;
          border-bottom: var(--border);
        }

        .nav-logo {
          font-family: var(--font-display);
          font-size: 1.375rem;
          font-weight: 600;
          color: var(--text-primary);
          letter-spacing: -0.02em;
          line-height: 1;
          text-decoration: none;
        }

        .nav-logo span { color: var(--accent-open); }

        .nav-tagline {
          font-family: var(--font-mono);
          font-size: 0.625rem;
          color: var(--text-tertiary);
          letter-spacing: 0.08em;
          text-transform: uppercase;
          margin-top: 4px;
        }

        .nav-items {
          flex: 1;
          padding: 1rem 0;
          display: flex;
          flex-direction: column;
          gap: 2px;
          list-style: none;
          overflow-y: auto;
        }

        .nav-item a {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 8px 1.25rem;
          font-size: 0.875rem;
          color: var(--text-secondary);
          text-decoration: none;
          border-radius: 0;
          transition: color 0.1s ease, background 0.1s ease;
          border-left: 2px solid transparent;
        }

        .nav-item a:hover {
          color: var(--text-primary);
          background: var(--bg-surface-2);
        }

        .nav-item.active a {
          color: var(--accent-open);
          border-left-color: var(--accent-open);
          background: color-mix(in srgb, var(--accent-open) 6%, transparent);
        }

        .nav-icon {
          font-size: 0.875rem;
          width: 18px;
          text-align: center;
          opacity: 0.8;
          flex-shrink: 0;
        }

        .nav-open-case a {
          color: var(--accent-open) !important;
          font-weight: 500;
        }

        .nav-section-label {
          padding: 0.75rem 1.25rem 0.25rem;
          font-family: var(--font-mono);
          font-size: 0.625rem;
          color: var(--text-tertiary);
          letter-spacing: 0.1em;
          text-transform: uppercase;
        }

        .nav-footer {
          padding: 1rem 1.25rem;
          border-top: var(--border);
        }

        .nav-user-email {
          font-family: var(--font-mono);
          font-size: 0.6875rem;
          color: var(--text-tertiary);
          margin-bottom: 8px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .nav-signout {
          background: none;
          border: none;
          color: var(--text-tertiary);
          font-size: 0.8125rem;
          font-family: var(--font-body);
          cursor: pointer;
          padding: 0;
          transition: color 0.1s;
          text-align: left;
        }

        .nav-signout:hover { color: var(--accent-severe); }
      `}</style>

      <nav className="nav-sidebar" aria-label="Main navigation">
        <div className="nav-wordmark">
          <Link href="/" className="nav-logo">
            No<span>Cap</span>
          </Link>
          <div className="nav-tagline">Threat Intelligence</div>
        </div>

        <ul className="nav-items" role="list">
          <li className="nav-section-label">Workspace</li>

          {NAV_ITEMS.map((item) => {
            const isActive =
              item.href === "/"
                ? pathname === "/"
                : pathname.startsWith(item.href);
            const isOpenCase = item.href === "/new";

            return (
              <li
                key={item.href}
                className={`nav-item ${isActive ? "active" : ""} ${isOpenCase ? "nav-open-case" : ""}`}
              >
                <Link href={item.href} aria-current={isActive ? "page" : undefined}>
                  <span className="nav-icon" aria-hidden="true">{item.icon}</span>
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>

        <div className="nav-footer">
          <div className="nav-user-email" title={userEmail}>
            {userEmail}
          </div>
          <button
            className="nav-signout"
            onClick={handleSignOut}
            id="nav-sign-out-btn"
            aria-label="Sign out"
          >
            Sign out
          </button>
        </div>
      </nav>
    </>
  );
}
