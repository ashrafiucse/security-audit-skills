# Security Audit — spa-vuln-app (knowledge-gap-closure round: WebAssembly delta)
Date: 2026-09-23 | Scope: fixture tree | Auditor: security-skills dev (IN-PROCESS run — ground-truth-aware, not blind recall)

## Stack
Client-side SPA embed page (index.html) + safe counter-example (safe-index.html). WSTG 4.13 delta: wasm loading discipline.

## Summary
| Severity | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 0 |

## Findings
### SEC-001: postMessage without origin check into innerHTML — CRITICAL
- **Where:** `index.html:8-10` — CWE-79 — cross-origin XSS.

### SEC-002: Sensitive payload postMessaged with '*' target — HIGH
- **Where:** `index.html:14` — CWE-200 — session token to any parent.

### SEC-003: WebAssembly module from client-controlled URL — HIGH
- **Where:** `index.html:17-19` — CWE-829 — query param → `fetch(url)` → `WebAssembly.instantiateStreaming` — attacker-chosen code in page origin (supply-chain artifact rules apply). Safe: fixed same-origin path (safe-index.html:17-18).

## Must NOT trigger (verified clean)
safe-index.html: origin-checked handler, textContent sink, explicit target origin, fixed-path wasm fetch — the instantiateStreaming grep hits both files; the fetch target is the triage discriminator.
