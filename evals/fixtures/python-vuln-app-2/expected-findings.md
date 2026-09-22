# python-vuln-app-2 — Expected findings

Ground truth for `evals/fixtures/python-vuln-app-2` (XXE + Python open
redirect). Live OSV dependency results are informational only — not ground
truth for this fixture (requirements are intentionally unpinned).

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | XXE — `lxml.etree.fromstring` on request body with default parser: entities resolved incl. external `file://` → file read / SSRF | app.py:15 | Critical |
| 2 | XML entity expansion DoS — stdlib `xml.etree.ElementTree.fromstring` on request body (no DTD protection → billion laughs) | app.py:22 | High |
| 3 | Open redirect — `redirect(request.args.get("next"))` without allowlist | app.py:29 | Medium |
| 4 | No authentication/authorization on any route (census 3/3 unguarded) — XML parser findings reachable anonymously (file-level anchor) | app.py:- | High |
| 5 | No security headers; no rate limiting — chain-critical multiplier on the entity-expansion DoS (file-level anchor) | app.py:- | Medium |
| 6 | Unpinned dependencies + no lockfile (file-level anchor) | requirements.txt:- | High |

## Must NOT trigger (near-misses — all in `safe_counterexamples.py`)

- `defusedxml.ElementTree.fromstring` (blocks DTDs/entities) — XXE safe form
- Redirect guarded by exact allowlist; `parse_url_checked` rejecting absolute and protocol-relative (`//evil.com`) targets
