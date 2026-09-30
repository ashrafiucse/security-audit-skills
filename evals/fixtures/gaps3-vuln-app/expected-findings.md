# gaps3-vuln-app — Expected findings

Ground truth for `evals/fixtures/gaps3-vuln-app` (proactive gap round:
multi-tenant scoping, deferred SSRF, archive extraction, comparison hygiene).

| # | Class | Finding | Where | Severity |
|---|---|---|---|---|
| 1 | Multi-tenant scoping | `/api/reports` returns ALL tenants' reports — no `tenantId` filter on a tenant-owned model (globex user gets acme financials); contrast with the scoped `/api/my-reports` | app.js:28-30 | Critical |
| 2 | Deferred SSRF (registration) | `POST /api/hooks` stores any URL with no scheme/host validation — internal/metadata URLs registrable | app.js:41-43 | High |
| 3 | Deferred SSRF (delivery) | delivery job fetches stored hook URLs with no fetch-time revalidation (DNS rebinding defeats registration-time checks); event payloads delivered to attacker URLs are an exfil channel | app.js:45-51 | High (Critical on cloud) |
| 4 | Archive extraction | `extractAllTo(..., true)` — zip-slip via `../` entry names + overwrite clobbers; no per-entry containment, no symlink rejection | app.js:55-59 | High |
| 5 | Comparison hygiene | redirect allowlist via raw `host.includes(h)` substring match — suffix/prefix hosts pass (`api.example.com.evil.io`) | app.js:63-71 | High |
| 6 | Flag/plan gating (generic layer) | `featureFlags = { 'import-leads': true, ... }` — dangerous capability default-true, no per-plan constraint | app.js:76 | High |
| 7 | Flag/plan gating (generic layer) | compose handler has NO flag check — capability gated in the UI only; handler is the enforcement point | app.js:83-87 | Critical |
| 8 | F9 amplification | `db.leads.findAll()` unbounded → per-row `sendMail` with attacker-influenced subject/body — one request → N emails | app.js:92-95 | Critical |
| 9 | Public email-trigger endpoint | `GET /leads/:id/send-verification-link` — no auth, no throttle, side effect on GET; ID enumeration = mail bomb | app.js:99-102 | Critical |
| 10 | Webhook receiver auth | `POST /webhooks/billing` acts on `req.body` with no sender-signature verification — forged events = free entitlements (pairs with F4 replay) | app.js:106-112 | Critical |
| 11 | Profile change → ATO | `POST /account/email` assigns `user.email = req.body.email` with session only — no current-password, no verify-before-swap; hijacked session silently owns the account | app.js:115-120 | High |
| 12 | One-time code disclosure | `GET /auth/email/code` returns the generated login code in the response body (`res.json({ sent: true, code })`) — request it for any known address, read it, log in (CVE-2026-97063 class) | app.js:123-128 | Critical |
| 13 | Static master code | `MASTER_LOGIN_CODE = '172839'` accepted by `POST /auth/email/login` for ANY account — public backdoor credential (CVE-2026-97064 class); also predictable `Math.random` codes, no expiry/attempts | app.js:130-140 | Critical |
| 14 | Webhook fail-open guard | `POST /hooks/deploy/:stackId` skips signature verification when `DEPLOY_WEBHOOK_SECRET` is unset/empty — unauthenticated stack redeploy (git clone + compose up), attacker-controlled compose = container-escape chain (Dockhand CVE-2026-53988 class; contrast row 10's missing check — here verification EXISTS but a config guard disables it) | app.js:144-155 | Critical |

## Must NOT trigger (near-misses — `safe-gaps3.js`)

- `/api/reports` scoped by `req.user.tenantId` (session tenant, not request data)
- Hook registration with scheme + anchored-host regex; safeExtract with per-entry containment + symlink rejection + no-overwrite
- Redirect with parsed `URL` + exact `Set.has(host)` equality
- `safe-gaps3.js` (appended safe shapes): `PLAN_CAPABILITIES` per-plan lookup (no flag map with true), compose handler behind `requireAuth, requireFlag('send-email'), rateLimit`, blast job with atomic `consumeBlastQuota` + `findAll({ where: { verified: true }, limit: 500 })`, verification sender as POST + `requireSigned` + `throttle`
- `safe-gaps3.js:78-90,93-100` — webhook behind `requireSignature(verifyBillingSignature)` + `withinReplayWindow`, HMAC over RAW bytes, `timingSafeEqual` compare
- `safe-gaps3.js:103-109` — email change behind `requireAuth, requireCurrentPassword` + `startEmailChange` verify-before-swap (no direct `user.email = req.body.email` assignment)
- `safe-gaps3.js:108-121` — code sender: `crypto.randomInt` generator, delivery to the STORED record's `user.email`, existence-neutral `{ sent: true }` response carrying NO code, throttled
- `safe-gaps3.js:123-132` — verify: single-use `codes.consume` + `timingSafeEqual`, throttled, zero static fallback constants anywhere in the file
- `safe-gaps3.js:134-141` — deploy webhook REJECTS when the secret is unset (fail-closed 503), then HMAC over raw bytes + `timingSafeEqual`; zero `!process.env.*WEBHOOK_SECRET` guard forms anywhere in the file
