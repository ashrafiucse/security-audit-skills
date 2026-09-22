# node-vuln-app-3 — Expected findings

Ground truth for `evals/fixtures/node-vuln-app-3` (route census, second-order
flows, query-builder raw sinks, multi-line construction). Live OSV dependency
results are informational only — not ground truth for this fixture.

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Stored XSS (second-order) — `user.bio` length-validated on write, rendered unescaped on read via EJS `<%- %>` | views/profile.ejs:3 (route app.js:25-28) | High |
| 2 | Unguarded admin route — no `requireAuth`/`requireAdmin` (route census finding; `GET /admin/users`) | app.js:32-36 | Critical |
| 3 | Query-builder raw sink — `knex.raw('SELECT ... ORDER BY ' + req.query.order)` | app.js:46 | Critical |
| 4 | SQL injection via multi-line template literal (built across lines 54-58; single-line greps miss it) | app.js:54-58 | Critical |
| 5 | Second-order command injection — queue worker `exec(`convert ${job.data.path} ...`)` trusts producer payload | app.js:65-68 | Critical |

## Must NOT trigger (near-misses)

- `app.get('/admin/settings', requireAuth, requireAdmin, ...)` — census row has both guards (app.js:38)
- Safe counterparts in `safe-counterexamples.js`:
  - `res.render` with `<%= %>` escaped read path (stored-XSS safe form)
  - `/admin/billing` guarded by both middlewares (census safe form)
  - `knex.raw('... ORDER BY ??', [col])` identifier binding (builder safe form)
  - `execFile('convert', [abs, ...])` with normalized + contained path (worker safe form)
- `postgres://db.internal.example.com/shop` connection string (no credentials — not a secret)
