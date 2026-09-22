# surface-vuln-app — Expected findings

Ground truth for `evals/fixtures/surface-vuln-app` (SAML, K8s RBAC
escalation verbs, serverless, dev-artifact leaks).

| # | Class | Finding | Where | Severity |
|---|---|---|---|---|
| 1 | SAML | `"strict": False` — validation framework disabled | saml_route.py:12 | High |
| 2 | SAML | `wantResponseSigned/wantAssertionsSigned: False` — unsigned responses/assertions accepted (signature-wrapping family enabler) | saml_route.py:14-15 | Critical |
| 3 | SAML | ACS URL not pinned, no audience validation — assertion replay/cross-SP | saml_route.py:17-21 | Critical |
| 4 | SAML | NameID consumed raw without format check (comment-injection class) | saml_route.py:31 | High |
| 5 | K8s RBAC | `escalate`/`bind` verbs granted — holders self-promote to cluster-admin | clusterrole.yaml:10 | Critical |
| 6 | K8s RBAC | cluster-wide `get/list` on secrets — reads every credential | clusterrole.yaml:13-14 | Critical |
| 7 | Serverless | wildcard `Action: "*"` / `Resource: "*"` function role | serverless.yml:12-13 | High |
| 8 | Serverless | live-format Stripe key in function env | serverless.yml:16 | Critical |
| 9 | Serverless | state-changing route with `authorizer: none` | serverless.yml:25-26 | Critical |
| 10 | Dev artifact | GITHUB_TOKEN in `.vscode/launch.json` env block | .vscode/launch.json:10 | High |
| 11 | Dev artifact | Bearer JWT in a Postman collection (shared-by-design surface) | shop-api.postman_collection.json:15 | Critical |

## Must NOT trigger (near-misses)

- All values are documented fakes (`ghp_Fake…`, `sk_(live|test)_Fake…`, `FAKE…` JWT) — the PATTERN+placement is the finding, not real creds (triage rule)
- A strict-mode SAML config with all want*Signed true, pinned ACS + audience (future safe file)
