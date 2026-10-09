# Security Audit — gaps3-vuln-app (triage conversion round, issues #58-#61)
Date: 2026-10-05 | Scope: working tree (fixture) | Auditor: security-skills dev (IN-PROCESS run — ground-truth-aware artifact validation, not blind recall; see scoreboard label)
Trigger: NVD digest #60 — ZITADEL CVE-2026-105207 (account linking without caller verification) + CVE-2026-105209 (enrollment code without target-tenant check) class conversions → auth-review §5 / §3. Rows 20-21 are reserved for the open PR #57 batch (WS command-forwarding + internal-key) — not part of this fixture state.

## Stack
Node/Express + queue worker (app.js) + safe counterpart (safe-gaps3.js). Actors: anonymous, authenticated tenant user, org admin, external IdP identities. Surfaces: tenant reports, webhook registration + delivery, zip import, redirect, marketing compose/blast pipeline, public lead endpoints, auth codes, admin switch, payment callback, IdP linking, enrollment codes.

## Summary
| Severity | Count |
|---|---|
| Critical | 15 |
| High | 6 |

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
- **Where:** `app.js:76` — **CWE-284** — `featureFlags = { 'import-leads': true, ... }`.

### SEC-007: Flag gated in UI only — compose handler has NO flag check — CRITICAL
- **Where:** `app.js:83-87` — **CWE-284** — handler is the enforcement point.

### SEC-008: F9 amplification — unbounded findAll → per-row sendMail — CRITICAL
- **Where:** `app.js:92-95` — **CWE-770** — one request → N emails.

### SEC-009: Public email-trigger endpoint on GET — CRITICAL
- **Where:** `app.js:99-102` — **CWE-770** — no auth, no throttle; ID enumeration = mail bomb.

### SEC-010: Webhook receiver acts on req.body without signature verification — CRITICAL
- **Where:** `app.js:106-112` — **CWE-345** — forged events = free entitlements.

### SEC-011: Email change without current password or verify-before-swap — HIGH
- **Where:** `app.js:115-120` — **CWE-620** — hijacked session silently owns the account.

### SEC-012: One-time code returned in the response body — CRITICAL
- **Where:** `app.js:123-128` — **CWE-200** — `res.json({ sent: true, code })` (CVE-2026-97063 class).

### SEC-013: Static master login code accepted for ANY account — CRITICAL
- **Where:** `app.js:130-140` — **CWE-798** — `MASTER_LOGIN_CODE = '172839'` (CVE-2026-97064 class).

### SEC-014: Webhook verification skipped when secret unset (fail-open) — CRITICAL
- **Where:** `app.js:144-155` — **CWE-1188** — unauthenticated stack redeploy (Dockhand CVE-2026-53988 class).

### SEC-015: Authz guard on RAW encoded URI, router dispatches decoded — CRITICAL
- **Where:** `app.js:157-169` — **CWE-177** — `/%61dmin/users` bypass (Cisco CVE-2026-76504 class).

### SEC-016: Setup/first-run route reachable post-install — CRITICAL
- **Where:** `app.js:172-179` — **CWE-306** — `POST /setup/restore` runs raw SQL (ground-station CVE-2026-103244 class).

### SEC-017: Non-secret identifier (hostname) accepted as device credential — CRITICAL
- **Where:** `app.js:181-188` — **CWE-798** — `findByHostname` (Fleet CVE-2026-103264 class).

### SEC-018: Authz predicate on request-derived principal — CRITICAL
- **Where:** `app.js:190-199` — **CWE-863** — capability checked on cookie-named user (DevKit Pro CVE-2026-14378 class).

### SEC-019: Callback that ESTABLISHES a session from request data — CRITICAL
- **Where:** `app.js:201-211` — **CWE-306** — `req.login(user)` from `paypal_param` (Divi Membership CVE-2026-19660 class).

### SEC-022: External-IdP account linking without caller verification — CRITICAL
- **Where:** `app.js:213-222` — **CWE-306** — `POST /auth/link` binds `req.body.idp_user_id` to the account named by `req.body.login_name` (`findByLoginName(req.body.login_name)`): no session, no primary factor, no ownership proof — knowing a login name attaches the attacker's IdP identity (ZITADEL CVE-2026-105207 class: AddIDPLink + identify-only Login V2 sessions). Safe shape: `requireAuth, requireStepUp` + identity from `idp.verify()` assertion, link to `req.user.id` only.

### SEC-023: Enrollment code issued without target-tenant check — CRITICAL
- **Where:** `app.js:225-235` — **CWE-863** — `POST /admin/enroll-code` checks only `req.headers['x-org-id']` then issues `codes.issue(target.id, 'passkey')` for any `req.body.user_id` — org-A admin enrolls org-B users (ZITADEL CVE-2026-105209 class). Safe shape: tenant-scoped lookup `findOne({ id, org_id: req.session.org_id })`.
