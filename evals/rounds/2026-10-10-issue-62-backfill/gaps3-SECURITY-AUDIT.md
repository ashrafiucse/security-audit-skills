# Security Audit — gaps3-vuln-app (KEV backfill round, issue #62)
Date: 2026-10-10 | Scope: working tree (fixture) | Auditor: security-skills dev (IN-PROCESS run — ground-truth-aware artifact validation, not blind recall; see scoreboard label)
Trigger: KEV backfill #62 — Kestra CVE-2026-49869 suffix-match auth-whitelist class → auth-review §1 third path-matching variant. Rows 20-23 arrived via merged PRs #57/#63; this round adds row 24 + exact-set safe counterpart and re-verifies all 24.

## Stack
Node/Express + queue worker (app.js) + safe counterpart (safe-gaps3.js). Actors: anonymous, tenant users, org admins, external IdP identities, agents.

## Summary
| Severity | Count |
|---|---|
| Critical | 18 |
| High | 6 |

## Findings
### SEC-001: Multi-tenant scoping — CRITICAL
- **Where:** `app.js:28-30` — `/api/reports` returns ALL tenants' reports — no `tenantId` filter on a tenant-owned model (globex user gets acme financials); contrast with the scope.
### SEC-002: Deferred SSRF (registration) — HIGH
- **Where:** `app.js:41-43` — `POST /api/hooks` stores any URL with no scheme/host validation — internal/metadata URLs registrable.
### SEC-003: Deferred SSRF (delivery) — HIGH (CRITICAL ON CLOUD)
- **Where:** `app.js:45-51` — delivery job fetches stored hook URLs with no fetch-time revalidation (DNS rebinding defeats registration-time checks); event payloads delivered to at.
### SEC-004: Archive extraction — HIGH
- **Where:** `app.js:55-59` — `extractAllTo(..., true)` — zip-slip via `../` entry names + overwrite clobbers; no per-entry containment, no symlink rejection.
### SEC-005: Comparison hygiene — HIGH
- **Where:** `app.js:63-71` — redirect allowlist via raw `host.includes(h)` substring match — suffix/prefix hosts pass (`api.example.com.evil.io`).
### SEC-006: Flag/plan gating (generic layer) — HIGH
- **Where:** `app.js:76` — `featureFlags = { 'import-leads': true, ... }` — dangerous capability default-true, no per-plan constraint.
### SEC-007: Flag/plan gating (generic layer) — CRITICAL
- **Where:** `app.js:83-87` — compose handler has NO flag check — capability gated in the UI only; handler is the enforcement point.
### SEC-008: F9 amplification — CRITICAL
- **Where:** `app.js:92-95` — `db.leads.findAll()` unbounded → per-row `sendMail` with attacker-influenced subject/body — one request → N emails.
### SEC-009: Public email-trigger endpoint — CRITICAL
- **Where:** `app.js:99-102` — `GET /leads/:id/send-verification-link` — no auth, no throttle, side effect on GET; ID enumeration = mail bomb.
### SEC-010: Webhook receiver auth — CRITICAL
- **Where:** `app.js:106-112` — `POST /webhooks/billing` acts on `req.body` with no sender-signature verification — forged events = free entitlements (pairs with F4 replay).
### SEC-011: Profile change → ATO — HIGH
- **Where:** `app.js:115-120` — `POST /account/email` assigns `user.email = req.body.email` with session only — no current-password, no verify-before-swap; hijacked session silently .
### SEC-012: One-time code disclosure — CRITICAL
- **Where:** `app.js:123-128` — `GET /auth/email/code` returns the generated login code in the response body (`res.json({ sent: true, code })`) — request it for any known address, re.
### SEC-013: Static master code — CRITICAL
- **Where:** `app.js:130-140` — `MASTER_LOGIN_CODE = '172839'` accepted by `POST /auth/email/login` for ANY account — public backdoor credential (CVE-2026-97064 class); also predicta.
### SEC-014: Webhook fail-open guard — CRITICAL
- **Where:** `app.js:144-155` — `POST /hooks/deploy/:stackId` skips signature verification when `DEPLOY_WEBHOOK_SECRET` is unset/empty — unauthenticated stack redeploy (git clone + c.
### SEC-015: Encoding-sensitive path authz (CWE-177) — CRITICAL
- **Where:** `app.js:157-169` — admin guard tests the RAW `req.url` while the router dispatches on the decoded path — `GET /%61dmin/users` skips the token check and still reaches `/a.
### SEC-016: Setup route reachable post-install — CRITICAL
- **Where:** `app.js:172-179` — `POST /setup/restore` runs raw `req.body.sql` with no auth and no "already installed?" guard — the first-run wizard stayed open as a front door (groun.
### SEC-017: Non-secret identifier as credential — CRITICAL
- **Where:** `app.js:181-188` — `POST /api/devices/login` authenticates on `findByHostname(req.body.hostname)` and issues a session — hostname is public/guessable, anyone who knows t.
### SEC-018: Authz on request-derived principal — CRITICAL
- **Where:** `app.js:190-199` — `POST /admin/switch/revert` looks up the user named by `req.cookies.original_user_id` and checks `manage_options` on THAT user — the capability check .
### SEC-019: Session-establishing callback — CRITICAL
- **Where:** `app.js:201-211` — `GET /payment/paypal/callback` decodes `paypal_param` from the query, takes `payload.user_id` as the identity, and calls `req.login(user)` — no signat.
### SEC-020: Command-forwarding WS handler — CRITICAL
- **Where:** `app.js:213-223` — `socket.on('agent:command', async (msg) => ...)` forwards `msg.command` straight to `agent.send({ cmd })` with no role check and no command allowlist .
### SEC-021: Internal key as master auth — CRITICAL
- **Where:** `app.js:225-235` — `app.use` middleware accepts `req.headers['x-internal-key'] == process.env.INTERNAL_KEY` for ANY endpoint — no path restriction, plain `==` compare, a.
### SEC-022: External-IdP account linking without caller verification — CRITICAL
- **Where:** `app.js:213-222` — `POST /auth/link` binds `req.body.idp_user_id` to the account named by `req.body.login_name` with NO session, NO primary factor, NO ownership proof — .
### SEC-023: Enrollment code without target-tenant check — CRITICAL
- **Where:** `app.js:225-235` — `POST /admin/enroll-code` validates only the caller's request tenant header (`x-org-id`), then issues a passkey enrollment code for ANY `req.body.user.
### SEC-024: Auth whitelist by path-suffix match — CRITICAL
- **Where:** `app.js:259-272` — `/api` middleware exempts any path ENDING in `/configs` from the token check (`req.path.endsWith('/configs')`) — the public endpoint is `/api/configs`.
