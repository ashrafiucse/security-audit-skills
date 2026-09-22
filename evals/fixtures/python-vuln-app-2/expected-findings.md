# python-vuln-app-2 — Expected findings

Ground truth for `evals/fixtures/python-vuln-app-2` (XXE + Python open
redirect). Live OSV dependency results are informational only — not ground
truth for this fixture (requirements are intentionally unpinned).

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | XXE — `lxml.etree.fromstring` on request body with default parser: entities resolved incl. external `file://` → file read / SSRF | app.py:15 | Critical |
| 2 | XML entity expansion DoS — stdlib `xml.etree.ElementTree.fromstring` on request body (no DTD protection → billion laughs) | app.py:22 | High |
| 3 | Open redirect — `redirect(request.args.get("next"))` without allowlist | app.py:29 | Medium |

## Must NOT trigger (near-misses — all in `safe_counterexamples.py`)

- `defusedxml.ElementTree.fromstring` (blocks DTDs/entities) — XXE safe form
- Redirect guarded by exact allowlist; `parse_url_checked` rejecting absolute and protocol-relative (`//evil.com`) targets
