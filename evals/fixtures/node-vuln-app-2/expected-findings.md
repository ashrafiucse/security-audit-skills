# node-vuln-app-2 — Expected findings

Ground truth for `evals/fixtures/node-vuln-app-2` (injection/authz classes not
covered by node-vuln-app). An audit should report all of the below; categories
must match, SEC ids may differ. Live OSV dependency results are informational
only — not ground truth for this fixture.

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | NoSQL operator injection — `findOne({email: req.body.email, password: req.body.password})` accepts `{"$ne": ""}` → auth bypass | app.js:24-26 | Critical |
| 2 | Prototype pollution — `deepMerge(featureFlags, req.body)` merges user-controlled keys (`__proto__`) into an existing object; `urlencoded({extended:true})` supplies nested bodies | app.js:31-41, 46-49 (sink at 47) | High (Critical with gadget) |
| 3 | ReDoS — nested quantifier `/^(a+)+$/` on unbounded user input | app.js:54-56 | High |
| 4 | Open redirect — `res.redirect(req.query.next)` without allowlist | app.js:59-62 | Medium |
| 5 | Trusted-header authorization — identity from spoofable `X-User-Id` header, no session/token | app.js:65-70 | Critical |
| 6 | TOCTOU race — single-use coupon: check (`coupon.used`) and claim (`updateOne`) are separate steps → replay | app.js:73-83 | High |
| 7 | Unsafe file upload — user filename verbatim (91), stored under served webroot (90: `public/uploads` + `express.static('public')` at 15), no filter/limits (93) | app.js:88-98 | High (Critical for parse-to-RCE chains) |
| 8 | WebSocket authz — no handshake auth middleware (`io.use` absent) + subscription without ownership check → IDOR over sockets | app.js:101-108 | Critical |

## Must NOT trigger (near-misses — all in `safe-counterexamples.js`)

- `stripOperators` allowlist before `findOne` (operator injection killed at the source)
- Destructured + type-checked fields spread into a **fresh** object (no user-controlled keys reach a target) — prototype pollution safe form
- `^[a-z0-9]+$` regex after a 64-char length cap (single quantifier, bounded input) — ReDoS safe form
- Redirect guarded by exact `Set` allowlist — open-redirect safe form
- `X-Request-Id` header read for **logging only** (never an authz input) — header-trust safe form
- Atomic `findOneAndUpdate({code, used: false}, {$set: {used: true}})` — TOCTOU safe form
- Upload with ext allowlist + CSPRNG filename + size cap + storage outside webroot
- Socket server with `ioSafe.use(jwt)` handshake auth and ownership check on subscribe
- Mongo URI `mongodb://mongo.internal.example.com:27017` (host only, no credentials — not a secret finding)
