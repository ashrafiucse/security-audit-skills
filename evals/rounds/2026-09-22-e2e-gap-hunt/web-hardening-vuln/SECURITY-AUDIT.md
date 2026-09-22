# Security Audit — web-hardening-vuln (eval fixture)
Date: 2026-09-22 | Scope: 433fb22 (working tree) | Auditor: security-skills v1.2.0-NOTAG-dev
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: not run (no network)

## Stack
Static HTML + vanilla JS frontend (`index.html`), Node/Express backend (`app.js`, 2 routes:
`POST /login`, `GET /items`). No dependency manifest, no lockfile, no infra/CI configs, no
database driver visible (`db` is referenced but undefined — fixture stub). No auth middleware,
no session store, no logging anywhere. Counter-example file `safe-index.html` present (audited
as context — see "What looks good").

## Summary
| Severity | Count |
|---|---|
| Critical | 0 |
| High | 5 |
| Medium | 7 |

Chains: **SEC-003 + SEC-001 → in-origin script execution** (compromised partner API injects
HTML; weak CSP allows inline/eval → account-context XSS). SEC-009 + SEC-010 → forgeable
"session" with no verification anywhere.

## Findings

### SEC-001: Weak CSP — unsafe-inline + unsafe-eval neutralize it — HIGH (chain-critical)
- **Where:** `index.html:7-8`
- **CWE:** CWE-79 / CWE-1021 (CSP misconfiguration)
- **Evidence:**
  ```html
  <meta http-equiv="Content-Security-Policy"
        content="default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval';">
  ```
- **Impact:** The policy is decorative: `'unsafe-inline'`+`'unsafe-eval'` re-allow inline
  script execution and eval, and `default-src *` permits exfil to any origin. Any HTML/XSS
  vector (see SEC-003) executes unimpeded.
- **Fix:** `default-src 'self'; script-src 'self' 'nonce-<random>'` (per-response nonce),
  remove all `unsafe-*`; add `connect-src`/`img-src` allowlists. The correct shape already
  exists in `safe-index.html:7`.
- **References:** OWASP CSP Cheat Sheet; MDN CSP.

### SEC-002: Third-party script without SRI — MEDIUM
- **Where:** `index.html:10`
- **CWE:** CWE-353 (Missing Support for Integrity Check)
- **Evidence:**
  ```html
  <script src="https://cdn.example-fake.com/analytics.js"></script>
  ```
- **Impact:** CDN or account compromise injects arbitrary script into every page load
  (classic analytics-CDN supply-chain vector).
- **Fix:** add `integrity="sha384-<hash>"` + `crossorigin="anonymous"` (safe-index.html:9-11
  shows the shape); pin and rotate hashes on release.

### SEC-003: Unsafe consumption of third-party API — upstream HTML into innerHTML — HIGH
- **Where:** `index.html:19` (fetch at :15)
- **CWE:** CWE-79 via CWE-841 (improper handling of inconsistent data from upstream)
- **Evidence:**
  ```js
  document.getElementById('feed').innerHTML = data.html;
  ```
- **Impact:** The partner API (`partner.example-fake.com/api/feed`) becomes an XSS
  distributor: any compromise, hijack, or malicious payload of the upstream `html` field
  executes in this origin. With SEC-001's CSP, script runs; session-bound actions are
  attacker-controlled (OWASP API10).
- **Fix:** render upstream data as text (`textContent` — safe-index.html:19) or sanitize
  server-side with an allowlist sanitizer before trusting any HTML.

### SEC-004: Upstream field trusted for authorization — HIGH
- **Where:** `index.html:21`
- **CWE:** CWE-284 / CWE-345 (insufficient verification of data authenticity)
- **Evidence:**
  ```js
  if (data.is_premium_user) { document.getElementById('feed').dataset.premium = '1'; }
  ```
- **Impact:** The partner API (or a MITM if TLS-only is ever relaxed) decides entitlements.
  Client-side flag may also gate UI the server must not trust — but as written, authorization
  input comes from an external, unauthenticated-by-the-client source.
- **Fix:** derive entitlements from a verified server-issued claim (safe-index.html:20
  re-derives from a signed `entitlements` claim); never let an upstream API field be an
  authorization decision input.

### SEC-005: No timeout on outbound fetch — MEDIUM
- **Where:** `index.html:15`
- **CWE:** CWE-1088 (SFP - external control); OWASP API4
- **Evidence:**
  ```js
  fetch('https://partner.example-fake.com/api/feed')
  ```
- **Impact:** a hung/slow upstream stalls the page indefinitely; at scale (if this pattern
  is mirrored server-side) it exhausts sockets/workers — resource consumption.
- **Fix:** `AbortController` + 5s timeout (demonstrated in safe-index.html:16-18).

### SEC-006: Session cookie without __Host- prefix and without SameSite — MEDIUM
- **Where:** `app.js:7`
- **CWE:** CWE-1004 (sensitive cookie without protections)
- **Evidence:**
  ```js
  res.cookie('session', 'tok123', { httpOnly: true, secure: true });
  ```
- **Impact:** no `__Host-` prefix means subdomain compromise (or cookie shadowing on
  sibling subdomains) can override the session cookie; missing `SameSite` leaves CSRF surface.
- **Fix:** `res.cookie('__Host-session', token, { httpOnly: true, secure: true,
  sameSite: 'strict' })` — the prefix pins Secure + no-domain + no-path attributes.

### SEC-007: CRLF injection into Location header — MEDIUM
- **Where:** `app.js:9`
- **CWE:** CWE-113 (HTTP response splitting)
- **Evidence:**
  ```js
  res.setHeader('Location', '/welcome?name=' + req.query.name);
  ```
- **Impact:** `?name=x%0d%0aSet-Cookie:...` splits/adds response headers on intermediaries
  that don't sanitize — cookie injection, cache poisoning, header smuggling.
- **Fix:** strip `\r\n`/`\0` from any user value before header use, and URL-encode the
  component: `'/welcome?name=' + encodeURIComponent(name)`.

### SEC-008: Unbounded list endpoint (API4) — MEDIUM
- **Where:** `app.js:13-16`
- **CWE:** CWE-770 (allocation without limits); OWASP API4
- **Evidence:**
  ```js
  app.get('/items', async (req, res) => {
    res.json(await db.items.find({})); // no limit/page
  });
  ```
- **Impact:** one request serializes the entire collection — memory/network DoS and bulk
  data disclosure of whatever `items` grows to contain.
- **Fix:** enforce `limit`/`cursor` with a server-side max page size (e.g. 100), plus a
  default sort for stable pagination.

### SEC-009: Static session token — every login receives the same value — HIGH
- **Where:** `app.js:7`
- **CWE:** CWE-330 / CWE-798 (use of insufficiently random / hardcoded value)
- **Evidence:**
  ```js
  res.cookie('session', 'tok123', ...);
  ```
- **Impact:** the session credential is a constant. Anyone who ever observes one session
  cookie (logs, referrer, XSS exfil) can forge sessions for all users; no logout/rotation
  is possible without redeploying the value. (No `randomBytes`/`uuid`/session store exists
  anywhere in the repo — verified.)
- **Fix:** `crypto.randomBytes(32).toString('base64url')` per login, stored server-side
  (session map/redis), rotated on privilege change.

### SEC-010: No authentication on any route — HIGH
- **Where:** `app.js` (global — route census: 0/2 routes guarded)
- **CWE:** CWE-306 (missing authentication for critical function)
- **Evidence:** census of `app.js`: both `POST /login` and `GET /items` are registered with
  no middleware; no session-verification code exists anywhere in the repo (grep for
  `session|token|auth|verify` returns only the cookie-set line).
- **Impact:** `/items` (data) and any future protected surface are reachable unauthenticated;
  combined with SEC-009 the entire "session" concept is forgeable.
- **Fix:** add session middleware and guard routes; census every new route.

### SEC-011: No rate limiting on /login — MEDIUM
- **Where:** `app.js:3-10`
- **CWE:** CWE-307
- **Evidence:** no limiter middleware registered (global grep: none).
- **Impact:** unlimited credential-stuffing attempts; compounds any enumeration behavior
  added later.
- **Fix:** per-IP + per-account limiter (e.g. `express-rate-limit`) on auth endpoints.

### SEC-012: No security headers and no security logging — MEDIUM
- **Where:** `app.js:4-5` (middleware setup — only `express()` present)
- **CWE:** CWE-693 / CWE-778
- **Evidence:** no helmet/CSP-headers/nosniff/X-Frame-Options middleware server-side; no
  logging of login success/failure anywhere.
- **Impact:** missing `X-Content-Type-Options`/frame protection on API responses; login
  events produce no audit trail (A09 minimum bar unmet — cannot answer "who logged in,
  when").
- **Fix:** `helmet()` (or equivalent header set) + structured login audit lines with
  actor/timestamp/outcome.

## What looks good
- `safe-index.html` demonstrates the correct patterns end-to-end: nonce-based CSP with no
  `unsafe-*`, SRI + `crossorigin` on the third-party script, `textContent` sink for upstream
  data, entitlement re-derived from a verified claim, and `AbortController` timeout on the
  outbound fetch — it is a working reference for fixing SEC-001..SEC-005.
- Cookie carries `httpOnly` and `secure` flags (partial credit — prefix/SameSite still missing).
- Secrets scan: clean — no provider keys, tokens, or connection strings committed.

## OWASP completeness gate
A01 covered (SEC-010); A02 n/a (no crypto use); A03 covered (SEC-003, SEC-007); A04 covered
(SEC-005, SEC-008, SEC-011); A05 covered (SEC-001/002/006/012); A06 **not assessed** (no
dependency manifest in fixture — nothing to scan; OSV not run, no network); A07 covered
(SEC-006, SEC-009, SEC-011); A08 covered (SEC-002 — unsigned third-party consumption); A09
covered (SEC-012); A10 covered via consumption angle (SEC-003/004 — fetch target is a
constant, no user-controlled URL → no classic SSRF).

## What would make this worse
- CDN account takeover + missing SRI (SEC-002) + weak CSP (SEC-001) = persistent script
  injection without touching the app.
- SEC-005 + SEC-008 together: slow upstream + full-collection serialization = cheap
  resource exhaustion.

## Recommended fix order
1. SEC-009 + SEC-010 (auth model: real tokens + route guards) — S/M effort
2. SEC-001 + SEC-003 (CSP nonces + text sink) — kills the XSS chain
3. SEC-007 (CRLF strip/encode) — S
4. SEC-006 (cookie prefix + SameSite) — S
5. SEC-002 (SRI) — S
6. SEC-004, SEC-008, SEC-005, SEC-011, SEC-012 — M
