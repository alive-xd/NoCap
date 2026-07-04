# Contributing to NoCap

We welcome contributions to NoCap! To maintain the platform's reliability, stability, and code quality, please adhere to the following development guidelines.

---

## 1. Development Principles

### 1.1. The Frozen Pipeline (ADR-001)
Every analysis execution must follow the strict pipeline flow:
```
Artifact ──► Parser ──► Evidence ──► Analyzer ──► Finding ──► Score
```
- **Parsers (`src/lib/parsers/`):** Must be purely functional and deterministic. They extract raw fields into atomic Evidence facts. They must **never** apply security judgment (e.g. labeling a port "malicious").
- **Analyzers (`src/lib/analyzers/`):** Must be stateless. They read the flat list of Evidence and output Findings. They must **never** make network calls, read raw payloads, or mutate existing evidence.

### 1.2. Document Every Threshold (ADR-002)
Any numeric threshold used by an Analyzer (e.g., CVSS limits, entropy limits, registration age) **must** cite an academic source, industry benchmark, or public blocklist standard in the comments and reasoning. No magic numbers.

---

## 2. Setting Up Local Development

1. Fork and clone the repository.
2. Initialize environment variables:
   ```bash
   cp .env.example .env.local
   ```
3. Set up a local database matching the DDL migrations in `supabase/migrations`.
4. Run the Next.js development server:
   ```bash
   npm run dev
   ```

---

## 3. Pull Request Guidelines

- **Strict Type Checking:** Always run `npx tsc --noEmit` before submitting your PR to ensure zero type check warnings or errors.
- **Access Scope Integrity:** Ensure all query resolvers filter user access using Row-Level Security policies to protect case ownership data.
- **CSRF Mitigations:** Mutating routes (POST/PATCH/DELETE) must enforce host validations in the proxy middleware.
- **Commit Messages:** Use descriptive semantic commit messages (e.g. `feat: ...`, `fix: ...`, `docs: ...`).

---

## 4. License
By contributing to NoCap, you agree that your contributions will be licensed under the project's **MIT License**.
