# Security Audit — node-vuln-app-2 (SAMPLE)

Sample report used to self-test `scripts/score_audit.py`. It deliberately:
reports findings 1-6 and 8 of the ground truth (missing #7 → recall 7/8),
and fabricates SEC-009 citing evidence that is not in ground truth (→ 1
phantom, precision 7/8). Not a real audit — do not copy as documentation.

Date: 2026-09-22 | Scope: sample | Auditor: security-skills (sample)

## Summary
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 2 |

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
- **Where:** `app.js:74`

### SEC-008: WebSocket — no handshake auth, no subscription authz — CRITICAL
- **Where:** `app.js:101`

### SEC-009: Insecure TLS configuration — HIGH
- **Where:** `app.js:200`
