# node-vuln-app — Expected findings

Ground truth for `evals/fixtures/node-vuln-app`. An audit should report all of
the below (exact SEC-NN ids may differ; categories must not).

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | SQL injection — template literal into query | app.js:23-26 | Critical |
| 2 | OS command injection — exec with user input | app.js:32 | Critical |
| 3 | Reflected XSS — user input in HTML response | app.js:35 | High |
| 4a | Weak hash (MD5) on password-like field | app.js:40 | Critical |
| 4b | Static/hardcoded IV for AES-CBC | app.js:45 | High |
| 5 | SSRF — fetch of user-supplied URL, no allowlist | app.js:51 | High |
| 6 | IDOR / missing authz on admin route | app.js:57-63 | Critical |
| 7 | Hardcoded DB password | app.js:12 | Critical |
| 8 | Hardcoded AWS access key id (+ logged) | app.js:13, 65 | Critical |
| 9 | Secret logged to console | app.js:65 | High |
| 10 | Missing security headers / helmet | app.js (global) | Medium |
| 11 | Vulnerable deps (express 4.17.3, lodash 4.17.20, moment 2.29.1 — via OSV live) | package.json | High (network-dependent) |
| 12 | A09: auth endpoint logs no success/failure audit events; raw User-Agent logged unsanitized (CWE-778 + CWE-117) | app.js:67-71 | Medium |
| 13 | express 4.17.3 — below vuln-db fix lines CVE-2024-43796 (4.21.2) / CVE-2024-45590 (4.21.0); transitive qs/path-to-regexp in known-vulnerable ranges (offline range check) | package.json:5 | High |
| 14 | Dormant vulnerable deps + lockfile hygiene — lodash 4.17.20 / moment 2.29.1 present but never imported (reachability: dormant); trimmed lockfile without integrity hashes | package.json:6-8 | Low/Medium |

## Must NOT trigger (near-misses)

- `DB_PASSWORD` constant referenced but empty string → would be a false positive
- Anything in `node_modules/` (should be excluded from scans)
