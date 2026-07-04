# Changelog

All notable changes to the NoCap project will be documented in this file.

---

## [1.0.0] - 2026-07-04

### Added
- **Parallel Query Execution:** Concurrently fetch intelligence sources (VirusTotal, AbuseIPDB, ip-api, WHOIS) via `Promise.allSettled` to lower target search latency.
- **CVE Watchlist Scanner:** Implemented NIST NVD vulnerability watcher cron triggers mapping watchlist items.
- **Scoring Claim Deduplication:** Enforced unique claim evaluations in the scoring engine to avoid double-counting.
- **Notes DELETE API Handler:** Added `DELETE` route endpoints with parent case ownership validations.
- **CSRF Middlewares Guard:** Added Origin/Referer verification checks in middleware to protect authenticated cookie sessions.
- **PostgREST Query Filters Sanitizer:** Sanitized input parameters in global search routes to prevent PostgREST syntax injection crashes.
- **Source-Specific Cache TTLs:** Configured cache lifetimes depending on lookup volatility (WHOIS 72h, IPASN 48h, VT 6h, AbuseIPDB 6h).
- **Whitespace Target Validator:** Added trims inside post request handlers to reject whitespace-only targets.
- **Case Sequence Auto-Retry Loop:** Auto-retry inserts with jitter backoffs to survive concurrent case number collisions.
