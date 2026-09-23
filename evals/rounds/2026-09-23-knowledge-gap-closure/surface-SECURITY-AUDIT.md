# Security Audit — surface-vuln-app (knowledge-gap-closure round: LDAP delta)
Date: 2026-09-23 | Scope: fixture tree | Auditor: security-skills dev (IN-PROCESS run — ground-truth-aware, not blind recall)

## Stack
Polyglot auth-surface fixture: SAML (python3-saml), K8s ClusterRole, serverless.yml, dev artifacts (.vscode/launch.json, Postman), LDAP (ldap3 + JNDI) — new in this round.

## Summary
| Severity | Count |
|---|---|
| Critical | 8 |
| High | 5 |
| Medium | 0 |

## Findings
### SEC-001: SAML strict mode disabled — HIGH
- **Where:** `saml_route.py:12` — CWE-346 — `"strict": False`.

### SEC-002: Unsigned SAML responses/assertions accepted — CRITICAL
- **Where:** `saml_route.py:14-15` — CWE-347.

### SEC-003: ACS URL not pinned, no audience validation — CRITICAL
- **Where:** `saml_route.py:17-21` — CWE-287 — replay/cross-SP assertions.

### SEC-004: NameID consumed raw — HIGH
- **Where:** `saml_route.py:31` — CWE-91 — comment-injection class.

### SEC-005: K8s escalate/bind verbs — CRITICAL
- **Where:** `clusterrole.yaml:10` — CWE-269 — self-promotion to cluster-admin.

### SEC-006: Cluster-wide secret reads — CRITICAL
- **Where:** `clusterrole.yaml:13-14` — CWE-200.

### SEC-007: Wildcard IAM role for function — HIGH
- **Where:** `serverless.yml:12-13` — CWE-732.

### SEC-008: Live-format Stripe key in env — CRITICAL
- **Where:** `serverless.yml:16` — CWE-798 — documented fake; pattern+placement is the finding.

### SEC-009: State-changing route with authorizer none — CRITICAL
- **Where:** `serverless.yml:25-26` — CWE-862.

### SEC-010: GITHUB_TOKEN in .vscode/launch.json — HIGH
- **Where:** `.vscode/launch.json:10` — CWE-798 — documented fake.

### SEC-011: Bearer JWT in Postman collection — CRITICAL
- **Where:** `shop-api.postman_collection.json:15` — CWE-798 — documented fake.

### SEC-012: LDAP anonymous bind as auth method — CRITICAL
- **Where:** `ldap_route.py:27` — CWE-287 — `authentication=ANONYMOUS` — binding ≠ identity verification.

### SEC-013: LDAP DN injection via concatenation — CRITICAL
- **Where:** `ldap_route.py:17` — CWE-90 — `"uid=" + uid + "," + BASE_DN`; safe: escape_dn_chars (safe-ldap_route.py:17).

### SEC-014: LDAP filter injection via f-string term — HIGH
- **Where:** `ldap_route.py:36` — CWE-74 — `f"(sAMAccountName={name})"`; safe: escape_filter_chars (safe-ldap_route.py:27).

### SEC-015: JNDI LDAP anonymous bind + concat principal — CRITICAL
- **Where:** `LdapAuth.java:11, 13-14` — CWE-287/CWE-90 — `SECURITY_AUTHENTICATION="none"` + `SECURITY_PRINCIPAL` concatenation; safe: "simple" + LdapUtils.escapeDN (SafeLdapAuth.java:11, 14).

## Must NOT trigger (verified clean)
safe-ldap_route.py / SafeLdapAuth.java: escaped DN + filter terms, "simple" auth — the DN/filter greps legitimately hit both files; escape-call context is the triage discriminator.
