# Security Policy

## Supported Versions

Only the latest release version of NoCap receives security patches.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## Reporting a Vulnerability

If you discover a security vulnerability in NoCap, please report it responsibly. **Do not open a public GitHub issue for security disclosures.**

Please send security reports directly to the maintainers at `security@nocap.local`. Include the following details:
1. **Description of the vulnerability** and its potential impact.
2. **Step-by-step instructions to reproduce** the issue (or a proof-of-concept script).
3. **Suggested remediation or patch** if you have one.

We will review your submission and respond within **48 hours** to coordinate a patched release before public disclosure.

---

## Security Core Guards
NoCap implements the following security mechanisms built-in:
- **Tenant Isolation:** Enforced via Row-Level Security (RLS) on all PostgreSQL tables.
- **CSRF Defense:** Middleware Origin/Referer verification on mutating endpoints.
- **Parametrized Filters:** Sanitized PostgREST syntax to avoid query injection.
