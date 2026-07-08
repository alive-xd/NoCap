# NoCap Architecture Decisions

This document outlines the core architecture and development principles for the NoCap project. 
As a solo portfolio project, these constraints act as internal guidelines to maintain a clean, maintainable, and predictable codebase.

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
