# Security Audit — node-vuln-app-2
Date: 2026-09-22 | Scope: working tree (repo @ v1.2.0, last commit touching fixture: feb64ab) | Auditor: security-skills v1.2.0
Knowledge base: 30 vuln-db entries (newest 2026-09-11) | Live checks: NOT RUN (no network — OSV.dev/KEV/endoflife skipped)

## Stack
Node/Express 4.19 + socket.io 4.7 + multer 1.4 + mongodb driver 6.5. Single-file app (`app.js`) plus a
counter-example file (`safe-counterexamples.js`, see "What looks good"). No auth/session middleware
anywhere; Mongo at internal host (no credentials in source — verified by secrets scan, 0 hits).
No lockfile. No tests, no CI config, no Docker/IaC files in this directory.

## Route census (auth-review §1)
| Route | Auth middleware | Ownership check | Status |
|---|---|---|---|
| POST /login | none (it IS the login) | n/a | rate-limit + operator injection findings |
| POST /settings | **none** | n/a | SEC-002 |
| GET /validate | none | n/a | SEC-003 |
| GET /logout | none | n/a | SEC-004 |
| GET /internal/orders | **none — header "identity"** | **none** | SEC-005 |
| POST /coupon/redeem | none | n/a | SEC-006 |
| POST /upload | none | n/a | SEC-007 |
| ws orders:subscribe (io, port 3001) | **none (no io.use)** | **none — caller-chosen userId** | SEC-008 |

## Summary
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 4 |
| Medium | 4 |

## Findings

### SEC-001: NoSQL operator injection on login — CRITICAL
- **Where:** `app.js:23-30`
- **CWE:** CWE-943 (NoSQL operator injection); OWASP A03
- **Evidence:**
  ```js
  const user = await db
    .collection('users')
    .findOne({ email: req.body.email, password: req.body.password });
  ```
- **Impact:** Request fields pass straight into the query document. `POST /login` with
  `{"email":{"$gt":""},"password":{"$ne":""}}` (or `$regex`) matches a record without knowing any
  credential → full unauthenticated account takeover of the first matching user.
- **Fix:** Strip `$`-prefixed keys recursively (see the safe counterpart in `safe-counterexamples.js:14-21`
  `stripOperators`), type-check values, and use an allowlisted field projection; or use an ODM schema
  that rejects operators.
- **References:** injection-flaws "NoSQL operator injection"

### SEC-002: Prototype pollution via deepMerge of request body — CRITICAL
- **Where:** `app.js:32-49` (sink at 47; deep-parsed body source at 14)
- **CWE:** CWE-1321; OWASP A03/A08
- **Evidence:**
  ```js
  app.use(express.urlencoded({ extended: true }));        // line 14 — nested attacker objects
  ...
  target[key] = deepMerge(target[key] || {}, source[key]); // line 35 — __proto__ walks into prototype
  ...
  deepMerge(featureFlags, req.body);                       // line 47 — unauthenticated POST /settings
- **Impact:** `POST /settings` with `__proto__`/`constructor.prototype` keys overwrites
  `Object.prototype` for the whole process (no auth on the route). Classic chains to RCE via
  `child_process` + `NODE_OPTIONS` or template-engine gadgets.
- **Fix:** Allowlist-pick fields into a fresh object (never merge raw bodies — safe form at
  `safe-counterexamples.js:32-40`), strip `__proto__`/`constructor`/`prototype` keys, or set
  `app.set('query parser', 'simple')` + `extended: false`.
- **References:** qs CVE-2022-24999 family (vuln-db) — library fix removes source, not sinks

### SEC-003: ReDoS — nested quantifier on unbounded input — HIGH
- **Where:** `app.js:52-56`
- **CWE:** CWE-1333; OWASP A03
- **Evidence:**
  ```js
  if (!/^(a+)+$/.test(req.query.token)) return res.status(400).send('bad');
  ```
- **Impact:** `"a".repeat(40) + "!"` backtracks catastrophically — Node's single event loop stalls for
  the whole process; trivial remote DoS on GET /validate.
- **Fix:** Cap input length (≤64) and use a single non-nested quantifier `/^[a-z0-9]+$/`
  (safe form at `safe-counterexamples.js:45-47`).

### SEC-004: Open redirect on logout — MEDIUM
- **Where:** `app.js:58-62`
- **CWE:** CWE-601; OWASP A01
- **Evidence:**
  ```js
  res.redirect(req.query.next || '/');
  ```
- **Impact:** `/logout?next=https://evil.example` bounces users to attacker-controlled pages —
  credential-relogin phishing after logout. No tokens carried in URL here, so Medium.
- **Fix:** Exact allowlist of destinations (safe form at `safe-counterexamples.js:52-55`); remember
  protocol-relative `//evil.com` bypasses naive relative checks.

### SEC-005: Trusted-header authorization (identity spoofing) — CRITICAL
- **Where:** `app.js:64-70`
- **CWE:** CWE-290 (authentication bypass by spoofing); OWASP A01
- **Evidence:**
  ```js
  const userId = req.headers['x-user-id'];
  const orders = await db.collection('orders').find({ userId }).toArray();
  ```
- **Impact:** Identity is taken from a client-settable header with no token/session check — anyone who
  can reach the service is any user. Valid only if an edge proxy strips inbound `X-User-Id` AND the app
  is unreachable directly; nothing in this repo shows either (no proxy config, port 3000 exposed).
- **Fix:** Real authentication (session/JWT verified server-side); derive userId from the verified
  identity, never from a header.

### SEC-006: TOCTOU race on single-use coupon — HIGH
- **Where:** `app.js:72-83`
- **CWE:** CWE-367; OWASP A04
- **Evidence:**
  ```js
  if (coupon.used) return res.status(409).send('already used');   // check
  await db.collection('coupons').updateOne({ code: req.body.code }, { $set: { used: true } }); // separate use
  ```
- **Impact:** Check and claim are two steps — concurrent `POST /coupon/redeem` replays pass both
  checks before either write lands; unlimited discount redemption under parallel load.
- **Fix:** Atomic conditional write: `findOneAndUpdate({ code, used: false }, { $set: { used: true } })`
  and fail on null result (safe form at `safe-counterexamples.js:58-66`).

### SEC-007: Unsafe file upload to served webroot — HIGH
- **Where:** `app.js:86-98` (webroot serving at `app.js:15`)
- **CWE:** CWE-434 (unrestricted upload); OWASP A04/A05
- **Evidence:**
  ```js
  destination: 'public/uploads',                                 // line 90 — under express.static('public')
  filename: (req, file, cb) => cb(null, file.originalname),       // line 91 — attacker filename verbatim
  // no fileFilter, no limits                                     // line 92-93
  ```
- **Impact:** Uploaded files are served from the webroot by `express.static`: SVG/HTML uploads = stored
  XSS on the app's origin; attacker-chosen filenames allow overwrites and `../`-shaped names; no size
  cap = disk exhaustion. Escalates toward Critical if any downstream server (nginx PHP exec, etc.)
  executes files from this path.
- **Fix:** Extension+MIME allowlist, CSPRNG filenames, size limit, storage outside the static root
  (complete safe form at `safe-counterexamples.js:70-83`); serve user content with
  `Content-Disposition: attachment` + `nosniff`.

### SEC-008: WebSocket — no handshake auth, no subscription authz (IDOR over sockets) — CRITICAL
- **Where:** `app.js:100-108`
- **CWE:** CWE-306 / CWE-639; OWASP A01
- **Evidence:**
  ```js
  io.on('connection', (socket) => {                 // no io.use(authMiddleware) anywhere
    socket.on('orders:subscribe', async (userId) => {
      const orders = await db.collection('orders').find({ userId }).toArray();
  ```
- **Impact:** Any client connects to port 3001 as anyone (no handshake token), and `orders:subscribe`
  takes a caller-chosen `userId` with no ownership check — full order-data read for arbitrary users
  over sockets.
- **Fix:** `io.use(jwt-verify)` handshake auth + ownership check `socket.user.id === userId`
  (safe form at `safe-counterexamples.js:86-105`); message handlers are routes — authz each one.

### SEC-009: No lockfile — non-reproducible dependency installs — HIGH
- **Where:** `package.json` (no `package-lock.json` in tree)
- **CWE:** CWE-1104; OWASP A06/A08
- **Evidence:** `package.json` declares `express ^4.19.2, mongodb ^6.5.0, multer ^1.4.5-lts.1, socket.io ^4.7.5`;
  `rg --files -g 'package-lock.json' -g 'yarn.lock'` → 0 results.
- **Impact:** Builds resolve ranges at install time — a compromised/renamed transitive dep slips in
  silently; CVE status of "the actual installed version" is unknowable.
- **Fix:** Commit a lockfile; pin CI to `npm ci`.

### SEC-010: Missing security headers — MEDIUM
- **Where:** `app.js` (global middleware)
- **CWE:** CWE-693; OWASP A05
- **Evidence:** No `helmet` in `package.json`; no header-setting middleware in `app.js` (grep: 0 hits for helmet/CSP/X-Frame-Options).
- **Impact:** No CSP (compounds SEC-007's stored XSS), no `X-Content-Type-Options`/frame protection,
  `x-powered-by` leaks stack.
- **Fix:** `app.use(helmet())` at minimum; a CSP without `unsafe-inline` once SEC-007 is fixed.

### SEC-011: No rate limiting on auth-sensitive endpoints — MEDIUM
- **Where:** `app.js:23` (`/login`), `app.js:72` (`/coupon/redeem`)
- **CWE:** CWE-770; OWASP A07/A04
- **Evidence:** grep for `rate.?limit|express-rate` → 0 hits; both endpoints accept unauthenticated writes.
- **Impact:** Brute-force on `/login` (compounding SEC-001), coupon-code grinding on `/redeem`.
- **Fix:** `express-rate-limit` on auth + redeem routes; add idempotency keys for redeem.

### SEC-012: No authentication layer at all; no auth audit events — MEDIUM
- **Where:** `app.js` (census table above — 0 of 8 routes have auth middleware; no login success/failure logging)
- **CWE:** CWE-306 / CWE-778; OWASP A07/A09
- **Evidence:** census table — every route row shows "none"; `console.log` used only for a request id.
- **Impact:** The app's security model depends on non-existent middleware; logins (even successful
  takeovers via SEC-001/SEC-005) leave no audit trail.
- **Fix:** Introduce a session/JWT middleware applied before guarded routes; log actor + outcome on
  auth events (see data-exposure A09 minimum bar).

## What looks good
- `safe-counterexamples.js` demonstrates the correct patterns for every code finding above:
  operator-stripping before queries, allowlisted merge, bounded regex, exact redirect allowlist,
  header-for-logging-only, atomic `findOneAndUpdate`, hardened upload (allowlist + CSPRNG name +
  cap + non-webroot storage), socket handshake auth with ownership checks.
- Mongo connection string carries no credentials (host-only URI) — verified by the secrets scan (0 hits).
- No hardcoded secrets anywhere in the tree (scanner output empty).

## Recommended fix order
1. SEC-005 + SEC-008 (identity spoofing + socket IDOR — trivial unauth data access, S effort)
2. SEC-001 (operator injection auth bypass, S)
3. SEC-002 (prototype pollution on unauthenticated route, M)
4. SEC-006 (coupon replay, S)
5. SEC-007 (upload hardening, M)
6. SEC-003/004/010/011/012 (S each)
7. SEC-009 (lockfile, S) + re-run dependency scan WITH network to close A06

## Completeness gate (OWASP)
A01 ✓ (005/008/012) · A02 ✓ assessed, no crypto usage · A03 ✓ (001/002/003/004/007) · A04 ✓ (006/007/011)
A05 ✓ (007/010) · A06 **not assessed** (no network; lockfile note only) · A07 ✓ (011/012) · A08 ✓ (002/007/009)
A09 ✓ (012) · A10 ✓ assessed — no outbound URL fetches in app code
