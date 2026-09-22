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

## Must NOT trigger (near-misses — `safe-gaps3.js`)

- `/api/reports` scoped by `req.user.tenantId` (session tenant, not request data)
- Hook registration with scheme + anchored-host regex; safeExtract with per-entry containment + symlink rejection + no-overwrite
- Redirect with parsed `URL` + exact `Set.has(host)` equality
