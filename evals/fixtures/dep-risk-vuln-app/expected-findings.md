# dep-risk-vuln-app — Expected findings

Ground truth for `evals/fixtures/dep-risk-vuln-app` (package-level risk with
clean-looking main code — see `dependency-vulns` Step 2.7 and
`references/dangerous-packages.md`). Live OSV results informational.

| # | Class | Finding | Where | Severity |
|---|---|---|---|---|
| 1 | Discontinued/unfixable | `vm2` present AND reachable — running user code in a discontinued, unpatched-sandbox-escape library | package.json:10, app.js:18 | High (Critical with untrusted plugins) |
| 2 | Dangerous usage | `_.merge(config, req.body)` — safe package, user-controlled keys (prototype pollution) | package.json:7, app.js:25 | High |
| 3 | Discontinued | `request` present and used with redirects on user URLs — unmaintained, SSRF-via-redirect never fixed | package.json:8, app.js:31 | High |
| 4 | Compromised release | `ua-parser-js` pinned to EXACTLY 0.7.29 — a malware-shipping release (cryptominer/credential dropper, no CVE) | package.json:9 | Critical (rotate credentials if ever installed) |
| 5 | Vendored copy | jQuery 1.8.3 committed under `public/vendor/` — `<3.5.0` thresholds (prototype pollution + XSS family); invisible to manifest scanners | public/vendor/jquery-1.8.3.min.js:1 | High |
| 6 | Hygiene | No lockfile — resolution risk compounds every finding above | package.json:- | High |
| 7 | Authz | No authentication on any route (census 0/3) — every package finding reachable unauthenticated (file-level anchor) | app.js:- | High |
| 8 | Hardening | No security headers; no rate limiting — chain-critical multiplier on the vm2 code-execution route (file-level anchor) | app.js:- | Medium |

## Must NOT trigger (near-misses — `safe-app.js`, `public/vendor/jquery-3.7.1.min.js`)

- `isolated-vm` usage (maintained alternative to vm2)
- Allowlist-picked settings merge (no user-controlled keys reach a target)
- `axios` with `maxRedirects: 0` on user URLs
- Vendored jQuery 3.7.1 (above thresholds — banner version is the verdict)
