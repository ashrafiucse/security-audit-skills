# spa-vuln-app — Expected findings

Ground truth for `evals/fixtures/spa-vuln-app` (client-side postMessage).

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | postMessage: no `event.origin` check + `innerHTML` sink — cross-origin XSS | index.html:8-10 | Critical |
| 2 | Sensitive payload (`session` token) sent with `postMessage(..., '*')` | index.html:14 | High |

## Must NOT trigger (near-misses — `safe-index.html`)

- Origin-checked handler with `textContent` sink
- `postMessage` with explicit allowed origin carrying non-sensitive data
