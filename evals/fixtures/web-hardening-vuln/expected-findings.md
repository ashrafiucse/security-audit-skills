# web-hardening-vuln — Expected findings

Ground truth for `evals/fixtures/web-hardening-vuln` (weak CSP, SRI, cookie
prefixes, CRLF, API4/API10). FAKE domains only.

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Weak CSP — `script-src 'unsafe-inline' 'unsafe-eval'` + `default-src *` neutralizes XSS protection | index.html:6-8 | High |
| 2 | Third-party script without `integrity=` (no SRI) | index.html:10 | Medium |
| 3 | Unsafe API consumption — upstream response HTML into `innerHTML` | index.html:19 | High |
| 4 | Upstream field trusted for authorization (`data.is_premium_user`) | index.html:21 | High |
| 5 | No timeout on outbound fetch (resource consumption) | index.html:15 | Medium |
| 6 | Auth/session cookie without `__Host-`/`__Secure-` prefix | app.js:7 | Medium |
| 7 | CRLF injection — user data into `Location` header (no `\r\n` strip) | app.js:9 | Medium |
| 8 | Unbounded list endpoint (no limit/pagination — API4) | app.js:15 | Medium |

## Must NOT trigger (near-misses — `safe-index.html`)

- CSP with nonces and no `unsafe-*` directives
- Third-party script WITH `integrity=` + `crossorigin`
- `textContent` sink for upstream data; entitlement derived from a validated claim
- `AbortController` + timeout on outbound fetch
