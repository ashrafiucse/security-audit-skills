# Security Audit — graphql-vuln-app
Date: 2026-09-22 | Scope: working tree (single-file fixture app) | Auditor: security-skills v1.2.0-1-g9a3b7cd
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: OSV.dev + CISA KEV — NOT RUN (no network)

## Stack
- Node/Express 4.17.1 + Apollo Server (apollo-server-express 3.10.0, graphql 15.8.0)
- Single GraphQL endpoint at `/graphql` (server.js, port 4000); schema-first SDL inline
- Auth: cookie-session 2.0.0 (cookie `sess`), HMAC signing key in source
- Data layer stubbed (`db.users`, `issueToken` undefined in-tree); no infra/CI files

## Summary
| Severity | Count |
|---|---|
| Critical | 3 |
| High | 6 |
| Medium | 6 |

**Chains (5):**
1. **CHAIN-1 (Critical): unauthenticated admin access** — introspection (SEC-008) discloses `adminDashboard` → no authz anywhere (SEC-001) → anyone queries the admin field.
2. **CHAIN-2 (Critical): session forgery** — hardcoded signing key `dev-secret` (SEC-003) → forge a valid `sess` cookie for any account, bypassing login entirely.
3. **CHAIN-3 (Critical): credential dump → offline cracking** — `allUsers` unbounded (SEC-010) + `passwordHash` returned to any caller (SEC-002) → full hash dump, crack at leisure.
4. **CHAIN-4 (High): cross-site mutations** — cookie-session auth without CSRF prevention (SEC-007) + default cookie flags (SEC-015) → attacker site executes mutations as the victim.
5. **CHAIN-5 (High): brute force** — `login` without rate limiting (SEC-006); GraphQL mutations bypass REST limiters.

## Findings

### SEC-001: No authorization wiring — every resolver is unauthenticated — CRITICAL
- **Where:** `server.js:34-47` (ApolloServer config: no `context` function), `server.js:49-53` (no auth middleware before `/graphql`)
- **CWE:** CWE-862 (Missing Authorization)
- **Evidence:**
  ```js
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true,
    playground: true,
    formatError: (err) => ({ ... }),
  });
  // no context: ({ req }) => ({ user: ... }) anywhere
  const app = express();
  app.use(require('cookie-session')({ name: 'sess', keys: ['dev-secret'] }));
  server.applyMiddleware({ app, path: '/graphql' });
  ```
- **Impact:** No resolver can even see the session (no context wiring), and no middleware gates the endpoint — `adminDashboard` (server.js:25), `allUsers`, and both mutations are reachable by any unauthenticated client. This is the root defect the other authz findings hang off.
- **Fix:** Add `context: ({ req }) => ({ user: req.session?.user })`, a `requireAuth`/`requireRole('admin')` guard checked inside every resolver (or field directives), and gate mutations in `applyMiddleware` middleware.
- **References:** OWASP A01

### SEC-002: Credential/PII field exposure — `passwordHash` returned to any caller — CRITICAL
- **Where:** `server.js:6` (schema), `server.js:21,23` (resolvers)
- **CWE:** CWE-200 (Exposure of Sensitive Information), CWE-522
- **Evidence:**
  ```graphql
  type User { id: ID! email: String! passwordHash: String! role: String! }
  ```
  ```js
  user: (_, { id }) => db.users.findById(id),
  allUsers: () => db.users.all(),
  ```
- **Impact:** Any (unauthenticated — see SEC-001) query selects `passwordHash`, `email`, and `role` for any/all users. Password hashes are offline-crackable inputs, not safe outputs; `role` disclosure maps the privilege landscape for SEC-001 abuse.
- **Fix:** Remove `passwordHash` (and `role` for non-admin callers) from the public type or mask it in a field resolver: `passwordHash: () => null`; return DTOs with an explicit allowlist of fields.
- **References:** graphql-security Step 2 (field-level authz, "CRITICAL for credentials/PII")

### SEC-003: Hardcoded weak session signing key (`dev-secret`) — CRITICAL
- **Where:** `server.js:51`
- **CWE:** CWE-798 (Use of Hard-coded Credentials), CWE-347
- **Evidence:**
  ```js
  app.use(require('cookie-session')({ name: 'sess', keys: ['dev-secret'] }));
  ```
- **Impact:** cookie-session HMACs the cookie with this key. It is committed, human-guessable, and environment-independent → anyone who reads the repo (or guesses it) forges a valid `sess` cookie with any session contents (`{user: {id: 1, role: 'admin'}}`) — full auth bypass without touching login (CHAIN-2). Note: the regex scanner misses this (`keys:` is not a secret-keyword) — found by manual config review.
- **Fix:** `keys: [process.env.SESSION_SECRET]` with a 32+ byte random value per environment; rotate (all sessions invalidate — intended).
- **References:** CWE-798; secrets-detection Step 2 (manual triage)

### SEC-004: IDOR — `user(id)` resolved without ownership check — HIGH
- **Where:** `server.js:21`
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Evidence:**
  ```js
  user: (_, { id }) => db.users.findById(id),
  ```
- **Impact:** Any caller fetches any user's record by changing `id` (horizontal escalation; combined with SEC-002 the record includes the password hash). Vertical variant: nothing restricts fetching admin rows.
- **Fix:** Scope to the session owner — `user: (_, { id }, ctx) => ctx.user && (ctx.user.id === id || ctx.user.isAdmin) ? db.users.findById(id) : null`.
- **References:** graphql-security Step 2; OWASP A01

### SEC-005: No query depth/complexity limits — nested-query DoS — HIGH
- **Where:** `server.js:34-47` (no `validationRules` in ApolloServer config)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Evidence:**
  ```js
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true,
    // no validationRules: [depthLimit(...), costAnalysis(...)]
  ```
- **Impact:** Cyclic/self-referential types (User → queries returning Users) allow deeply nested queries that exhaust CPU/memory in a single unauthenticated request — single-request DoS.
- **Fix:** `validationRules: [depthLimit(7), costAnalysis({ maximumCost: 1000 })]` (graphql-depth-limit / graphql-cost-analysis); enable persisted queries for public clients.
- **References:** graphql-security Step 1; OWASP A04

### SEC-006: No rate limiting on `login` / `resetPassword` — HIGH
- **Where:** `server.js:29-30`
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Evidence:**
  ```js
  login: async (_, { email, password }) => issueToken(email, password),
  resetPassword: async (_, { email }) => true,
  ```
- **Impact:** GraphQL mutations bypass REST-path rate limiters; unlimited password brute force per IP (compounds with SEC-002 hash dumping for targeted cracking).
- **Fix:** Per-IP/per-account limiter in the `/graphql` middleware (graphql-rate-limit directive or express-rate-limit ahead of `applyMiddleware`); lockout + backoff on failures.
- **References:** graphql-security Step 3; OWASP A07

### SEC-007: Cookie-session auth without CSRF prevention — HIGH
- **Where:** `server.js:51-52`
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **Evidence:**
  ```js
  app.use(require('cookie-session')({ name: 'sess', keys: ['dev-secret'] }));
  server.applyMiddleware({ app, path: '/graphql' });   // csrfPrevention not configured
  ```
- **Impact:** Ambiguous-content-type POSTs to `/graphql` execute mutations (`login` state changes, future writes) cross-site with the victim's cookie (CHAIN-4). Apollo's CSRF prevention exists for exactly this and is absent.
- **Fix:** `csrfPrevention: true` in the ApolloServer config, plus content-type validation and `SameSite=Lax/Strict` cookie (see SEC-015).
- **References:** graphql-security Step 1; OWASP A01

### SEC-008: Introspection + Playground enabled; admin types enumerable — HIGH
- **Where:** `server.js:38-39`
- **CWE:** CWE-200
- **Evidence:**
  ```js
  introspection: true,
  playground: true,
  ```
- **Impact:** Full schema oracle — attacker enumerates `adminDashboard`, `User.passwordHash`, and every mutation without touching the app; Playground ships an interactive query console. Elevation per graphql-security: admin/internal types are visible in the schema (feeds CHAIN-1).
- **Fix:** Disable in production builds (`introspection: process.env.NODE_ENV !== 'production'`, same for playground) or gate both behind auth.
- **References:** graphql-security Step 1; OWASP A05

### SEC-009: Error formatter leaks stack traces and internals — MEDIUM
- **Where:** `server.js:41-45`
- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
- **Evidence:**
  ```js
  formatError: (err) => ({
    message: err.message,
    extensions: err.extensions,
    stack: typeof err.stack === 'string' ? err.stack.split('\n').slice(0, 4) : undefined,
  }),
  ```
- **Impact:** Partial stack traces + internal extensions (paths, library versions, resolver internals) returned to clients on every error — reconnaissance aid; stack trimming to 4 lines is not sanitization.
- **Fix:** In production mask to `{ message: err.message }` (or map known errors to safe codes); never send `stack`/`originalError`.
- **References:** graphql-security Step 1; OWASP A05

### SEC-010: `allUsers` unbounded — full-table dump, no pagination — MEDIUM
- **Where:** `server.js:9,23`
- **CWE:** CWE-770 (Allocation of Resources Without Limits)
- **Evidence:**
  ```graphql
  allUsers: [User!]!
  ```
  ```js
  allUsers: () => db.users.all(),
  ```
- **Impact:** No `first`/`last`/limit — one query returns every row (resource exhaustion vector; multiplies SEC-002's credential dump into a full dump).
- **Fix:** Relay-style connections or hard `limit` argument (default ≤ 50, max enforced server-side).
- **References:** graphql-security Step 3

### SEC-011: express 4.17.1 — below the CVE-2022-24999 fix line (transitive qs prototype pollution) — HIGH
- **Where:** `package.json:6` (express 4.17.1; fixed line 4.17.3)
- **CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
- **Evidence:**
  ```json
  "express": "4.17.1",
  ```
- **Impact:** express <4.17.3 resolves qs with the bracket-key prototype-pollution bug (`?__proto__[x]=1` pollutes `Object.prototype` via query parsing) — a documented RCE-chainable primitive on Node. Version-only finding (offline): confirm the installed tree when network is available.
- **Fix:** `npm install express@^4.19` (current line) + commit a lockfile (see SEC-012).
- **References:** vuln-db entry CVE-2022-24999; OWASP A06/A08

### SEC-012: No lockfile — non-reproducible dependency installs — MEDIUM
- **Where:** `package.json:1` (no `package-lock.json`/`yarn.lock` in tree — verified: 0 results)
- **CWE:** CWE-1104
- **Evidence:** `ls package-lock.json yarn.lock` → "No such file or directory" for both.
- **Impact:** Install-time range resolution: a compromised/renamed transitive dependency slips in silently between builds; exact-version audits (SEC-011) are unverifiable without it. Rated Medium per the master triage rubric (hygiene), elevated from Low because vulnerable ranges are already pinned loose.
- **Fix:** Commit `package-lock.json`; CI installs with `npm ci`.
- **References:** dependency-vulns Step 2

### SEC-013: No security headers on the response path — MEDIUM
- **Where:** `server.js:49-53` (global middleware — no helmet/CSP/X-Frame-Options anywhere)
- **CWE:** CWE-693 (Protection Mechanism Failure)
- **Evidence:** 0 hits for helmet/CSP/X-Frame-Options in server.js; Express defaults leak `x-powered-by`.
- **Impact:** No CSP (compounds any future XSS/Playground surface), no clickjacking protection, stack fingerprint via `x-powered-by`.
- **Fix:** `app.use(helmet())` before `applyMiddleware`; disable `x-powered-by`.
- **References:** config-hardening §2; OWASP A05

### SEC-014: No audit logging on auth mutations (A09) — MEDIUM
- **Where:** `server.js:29-30`
- **CWE:** CWE-778 (Insufficient Logging)
- **Evidence:** No logging of any kind in the file (0 `console.`/logger hits); `login`/`resetPassword` emit no success/failure events.
- **Impact:** Successful brute force (SEC-006) or forged-cookie access (SEC-003) leaves no trace — undetectable compromise.
- **Fix:** Structured log line on login success/failure (actor, outcome, timestamp), reset requests, and any admin mutation.
- **References:** data-exposure A09 minimum bar; OWASP A09

### SEC-015: Session cookie flags not configured — MEDIUM
- **Where:** `server.js:51`
- **CWE:** CWE-614 (Sensitive Cookie Without Secure Flag), CWE-1275
- **Evidence:**
  ```js
  app.use(require('cookie-session')({ name: 'sess', keys: ['dev-secret'] }));
  ```
- **Impact:** No `secure: true` (cookie travels over plain HTTP), no explicit `sameSite` (browser defaults vary; cookie-session does not set it) — compounds CHAIN-4 and eavesdropping exposure.
- **Fix:** `{ ..., secure: true, sameSite: 'lax', httpOnly: true }` (httpOnly is default — keep it explicit).
- **References:** auth-review §4; OWASP A02/A05

## What looks good
- No injection surface: no SQL string building, `exec`/eval, or template rendering anywhere (A03/A08 clean by absence)
- No outbound fetches (A10 SSRF surface absent)
- Secrets regex scan of the tree: clean (the one weak key found manually, SEC-003, is below the scanner's keyword set — not a scanner false negative)
- Fixture discipline: clearly fake data (`db`/`issueToken` stubs prevent unverifiable crypto/authn claims)

## Completeness gate (OWASP Top 10)
| Cat | Status |
|---|---|
| A01 Broken Access Control | SEC-001, 004, 007 |
| A02 Cryptographic Failures | SEC-002, 003, 015 |
| A03 Injection | scanned — no sinks present (not assessed → no surface) |
| A04 Insecure Design | SEC-005, 006, 010 |
| A05 Misconfiguration | SEC-008, 009, 013 |
| A06 Vulnerable Components | SEC-011, 012 (live OSV: not run — no network) |
| A07 Auth Failures | SEC-006, 015 |
| A08 Integrity | scanned — no CI/deserialization surface |
| A09 Logging | SEC-014 |
| A10 SSRF | scanned — no outbound calls |

**Not run:** OSV.dev / CISA KEV / endoflife live checks (no network); `npm audit` (tool present but requires network). Runtime/exploit testing out of scope (read-only audit).

## Recommended fix order
1. SEC-003 (critical, effort S) — rotate the session key to env secret; kills CHAIN-2
2. SEC-001 (critical, S/M) — add context + per-resolver guards; kills CHAIN-1
3. SEC-002 (critical, S) — strip `passwordHash`/`role` from the public type; kills CHAIN-3
4. SEC-006 + SEC-007 (high, S) — rate limiting + `csrfPrevention: true`
5. SEC-005 (high, S) — depth/complexity limits
6. SEC-008, 009, 013, 015 (medium, S each) — prod flags, error masking, helmet, cookie flags
7. SEC-011 + SEC-012 (S) — upgrade express, commit lockfile, re-run OSV when online
8. SEC-010, SEC-014 (M) — pagination, audit logging
