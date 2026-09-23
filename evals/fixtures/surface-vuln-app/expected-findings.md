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
| 12 | LDAP | Anonymous bind accepted as an auth method (`authentication=ANONYMOUS`) | ldap_route.py:27 | Critical |
| 13 | LDAP | DN injection — bind DN built by concatenation (`"uid=" + uid + ",...`) | ldap_route.py:17 | Critical |
| 14 | LDAP | Filter injection — f-string filter term (`f"(sAMAccountName={name})"`), no escape | ldap_route.py:36 | High |
| 15 | LDAP (Java) | `Context.SECURITY_AUTHENTICATION` = `none` (anonymous bind) + `SECURITY_PRINCIPAL` concat DN | LdapAuth.java:11, 13-14 | Critical |
| 16 | K8s RBAC | Wildcard `apiGroups`/`resources` + mutating verbs — unbounded cluster-wide write for any holder (IBM-Concert class, converted 2026-09-23) | clusterrole.yaml:17-20 | High |

## Must NOT trigger (near-misses)

- All values are documented fakes (`ghp_Fake…`, `sk_(live|test)_Fake…`, `FAKE…` JWT) — the PATTERN+placement is the finding, not real creds (triage rule)
- A strict-mode SAML config with all want*Signed true, pinned ACS + audience (future safe file)
- `safe-ldap_route.py:17` — DN composed with `escape_dn_chars(uid)` (the escape call is the triage discriminator; the DN-concat grep legitimately hits both files)
- `safe-ldap_route.py:27` — filter term wrapped in `escape_filter_chars(name)`
- `SafeLdapAuth.java:11,14` — `SECURITY_AUTHENTICATION="simple"` + DN escaped via `LdapUtils.escapeDN(uid)`
- `hardened-clusterrole.yaml:10-12` — scoped Role: named apiGroup, named resources, read-only verbs; zero wildcard rows (the wildcard census grep must stay silent here)
