# Security Audit — node-vuln-app-2 (SAMPLE)

Sample report used to self-test `scripts/score_audit.py`. It deliberately:
reports 10 of 11 ground-truth rows (misses the lockfile row → recall 0.909),
includes one file-level citation pattern (bare `app.js`) to exercise the
`file:-` anchor support, and fabricates SEC-011 citing a file that does not
exist (→ 1 phantom, precision 0.909). Not a real audit — do not copy.

Date: 2026-09-22 | Scope: sample | Auditor: security-skills (sample)

## Summary
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 4 |
| Medium | 2 |

## Findings

### SEC-001: NoSQL operator injection — CRITICAL
- **Where:** `app.js:26`

### SEC-002: Prototype pollution — HIGH
- **Where:** `app.js:47`

### SEC-003: ReDoS — HIGH
- **Where:** `app.js:54`

### SEC-004: Open redirect — MEDIUM
- **Where:** `app.js:61`

### SEC-005: Trusted-header authorization — CRITICAL
- **Where:** `app.js:67`

### SEC-006: TOCTOU race on coupon redeem — HIGH
- **Where:** `app.js:75`

### SEC-007: Unsafe file upload — HIGH
- **Where:** `app.js:88`

### SEC-008: WebSocket authz missing — CRITICAL
- **Where:** `app.js:101`

### SEC-009: Missing security headers — MEDIUM
- **Where:** `app.js` (global middleware — no helmet/CSP anywhere in the response path)

### SEC-010: No authentication layer; no login audit events — HIGH
- **Where:** `app.js` (route census: 0 of 8 routes carry auth middleware)

### SEC-011: Insecure TLS configuration — HIGH
- **Where:** `config/settings.json:12`
