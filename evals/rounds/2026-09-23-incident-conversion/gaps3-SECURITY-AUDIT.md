# Security Audit — gaps3-vuln-app (generic-layer incident conversion round)
Date: 2026-09-23 | Scope: working tree (fixture) | Auditor: security-skills dev (IN-PROCESS run — ground-truth-aware artifact validation, not blind recall; see scoreboard label)
Trigger: user architecture directive — incident classes must live in the GENERIC layer (auth-review/flow-security), not only the framework skill where the incident happened. This round proves the flag-gating + F9 classes detect on a NON-Laravel stack (Node/Express).

## Stack
Node/Express + queue worker (app.js) + safe counterpart (safe-gaps3.js). Actors: anonymous, authenticated tenant user, trial-tenant admin (plan-constrained persona), worker/queue. Surfaces: tenant reports, webhook registration + delivery, zip import, redirect, marketing compose/blast pipeline, public lead endpoints.

## Summary
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 5 |

## Findings
### SEC-001: Multi-tenant scoping — `/api/reports` returns ALL tenants' reports — CRITICAL
- **Where:** `app.js:28-30` — **CWE-639/200** — no `tenantId` filter; safe counterpart scopes by session tenant.

### SEC-002: Deferred SSRF — hook registration accepts any URL — HIGH
- **Where:** `app.js:41-43` — **CWE-918** — internal/metadata URLs registrable.

### SEC-003: Deferred SSRF — delivery fetches stored URLs without fetch-time revalidation — HIGH
- **Where:** `app.js:45-51` — **CWE-918** — DNS rebinding defeats registration-time checks; event payloads exfil.

### SEC-004: Archive extraction — zip-slip + overwrite — HIGH
- **Where:** `app.js:55-59` — **CWE-22** — `extractAllTo(..., true)`.

### SEC-005: Comparison hygiene — substring host allowlist — HIGH
- **Where:** `app.js:63-71` — **CWE-697** — `host.includes(h)`; exact `Set.has` is the safe shape.

### SEC-006: Feature flag default-true for a dangerous capability — HIGH
- **Where:** `app.js:76` — **CWE-1188** — `featureFlags = { 'import-leads': true, ... }` — capability exists for every plan incl. trials. Safe shape: per-plan capability lookup (`PLAN_CAPABILITIES` in safe-gaps3.js).

### SEC-007: Capability gated in the UI only — handler has no flag check — CRITICAL
- **Where:** `app.js:83-87` — **CWE-284** — compose handler (attacker-controlled subject/body into the queue) never checks the flag; menu hiding is cosmetic; the handler is the enforcement point. Safe shape: `requireAuth, requireFlag('send-email'), rateLimit` before the handler (safe-gaps3.js).

### SEC-008: F9 outbound-message amplification — one request → N emails — CRITICAL
- **Where:** `app.js:92-95` — **CWE-770/406** — `db.leads.findAll()` unbounded → per-row `sendMail` with attacker-influenced subject/body. Safe shape: atomic `consumeBlastQuota` inside the job + `findAll({ where: { verified: true }, limit: 500 })`.

### SEC-009: Public email-triggering endpoint on a GET — CRITICAL
- **Where:** `app.js:99-102` — **CWE-352/1284** — `GET /leads/:id/send-verification-link` — no auth, no throttle, side effect on GET; ID enumeration = mail bomb with zero flags. Safe shape: POST + signed + throttled (safe-gaps3.js).

## Must NOT trigger (verified clean)
safe-gaps3.js appended shapes: plan-capability lookup (no flag-map true), gated+throttled compose handler, quota'd+capped blast job, POST+signed verification sender — 4 no-match self-test rules pin all four raw forms at zero.

## Census receipts
| Census | hits | dispositioned |
|---|---|---|
| Flag map defines | 1 | 1 (default-true → SEC-006) |
| Compose handler middleware | 1 vuln + 1 safe | 2 (absence of flag middleware = SEC-007) |
| Unbounded fetches feeding senders | 1 | 1 (safe uses chained where+limit — not matched) |
| Email-verb public routes | 1 | 1 (GET + no throttle = SEC-009) |
