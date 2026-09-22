# graphql-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Introspection + Playground forced on in production | server.js:38-39 | Medium (High — admin-ish types visible) |
| 2 | `formatError` leaks extensions + stacktrace lines | server.js:41-45 | Medium |
| 3 | IDOR — `user(id)` resolver, no ownership check | server.js:22 | High |
| 4 | `allUsers` unbounded + returns `passwordHash` field | server.js:24, schema line 4 | Critical (PII + cred material) |
| 5 | `adminDashboard` query with no role check | server.js:26 | High |
| 6 | `login`/`resetPassword` mutations with no rate limiting | server.js:30-31 | High |
| 7 | No depth/complexity limit (`validationRules` absent) | server.js:46 | High |
| 8 | Cookie-session auth + CSRF protection not configured | server.js:49-50 | High |
| 9 | `dev-secret` as cookie signing key (weak hardcoded) | server.js:50 | High |
| 10 | express 4.17.1 — below the CVE-2022-24999 fix line (transitive qs prototype pollution; vuln-db entry) | package.json:7 | High |
| 11 | No lockfile — non-reproducible installs (file-level anchor) | package.json:- | Medium |

## Must NOT trigger

- `nonce` argument echo in `adminDashboard` (not reflective XSS — returned as plain string in JSON field)
- GraphQL `ID` type itself (not a finding)
