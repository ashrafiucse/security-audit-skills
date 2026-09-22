# Security Audit — python-vuln-app-2
Date: 2026-09-22 | Scope: fixture working tree (parent repo @433fb22) | Auditor: security-skills v1.2.0-18-ge977d73-dev
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: NOT RUN (no network) — OSV/KEV/endoflife skipped

## Stack
Python/Flask microservice; 3 request handlers (`/import` POST, `/feed` POST, `/logout` GET) + a counter-example module (`safe_counterexamples.py`, 1 route + 2 helpers). Deps declared unpinned: `flask`, `lxml`, `defusedxml` (requirements.txt:1-3). No DB, no templates, no crypto, no infra files, no CI.

## Summary
| Severity | Count |
|---|---|
| Critical | 1 |
| High | 3 |
| Medium | 2 |

**Chains:** SEC-002 (billion-laughs parser) + SEC-005 (no rate limit) → unauthenticated, unthrottled CPU/memory exhaustion of every worker. SEC-001's external-entity variant is itself an SSRF/file-read primitive from an unauthenticated endpoint.

**Route census:** 3/3 routes in `app.py` have NO auth middleware and no session/token code anywhere in the module.

## Findings

### SEC-001: XXE — lxml default parser resolves entities on user-controlled XML — CRITICAL
- **Where:** `app.py:15` (route `POST /import`, app.py:12-16)
- **CWE:** CWE-611 (Improper Restriction of XML External Entity Reference); CWE-776
- **Evidence:**
  ```python
  tree = etree.fromstring(request.get_data())
  return etree.tostring(tree)
  ```
- **Impact:** `lxml.etree.fromstring` with the default parser resolves DTDs and entities, including EXTERNAL entities (`file://` reads of `/etc/passwd`, app secrets; `http://`/`ftp://` fetches to internal hosts = SSRF; parameter-entity exfiltration of file contents to an attacker URL). Unauthenticated POST body is the document. File disclosure + internal-network probing on every request.
- **Fix:** `defusedxml` is ALREADY a dependency (used correctly in `safe_counterexamples.py:14`) — route this handler through it:
  ```python
  import defusedxml.ElementTree as SafeET
  tree = SafeET.fromstring(request.get_data())          # blocks DTDs/entities
  ```
  lxml-only alternative: `etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)` passed as second arg — but prefer defusedxml.
- **References:** CWE-611; OWASP A03; `injection-flaws` XXE section; vuln-db PyYAML/CVE-2020-14343 sibling class.

### SEC-002: XML entity-expansion DoS — stdlib parser on user input — HIGH
- **Where:** `app.py:22` (route `POST /feed`, app.py:19-23)
- **CWE:** CWE-776 (Improper Restriction of Recursive Entity References)
- **Evidence:**
  ```python
  root = ET.fromstring(request.get_data())
  return root.tag or "ok"
  ```
- **Impact:** stdlib `xml.etree` does not fetch external entities but EXPANDS internal entity definitions — a ~1KB "billion laughs" document (nested `<!ENTITY` definitions) expands into gigabytes in RAM/CPU and stalls the worker. Unauthenticated and (with SEC-005) unthrottled → repeatable full-service DoS.
- **Fix:** same as SEC-001 — `defusedxml.ElementTree.fromstring` blocks entity expansion (it forbids DTDs outright). Unbounded request-size caps at the proxy additionally bound the damage.
- **References:** CWE-776; `injection-flaws` XXE section ("stdlib xml.* → billion laughs → High").

### SEC-003: Open redirect — unvalidated `next` parameter — MEDIUM
- **Where:** `app.py:29` (route `GET /logout`, app.py:26-29)
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **Evidence:**
  ```python
  return redirect(request.args.get("next", "/"))
  ```
- **Impact:** attacker sends `https://app/logout?next=https://evil.example.com/phish` (or `//evil.com`, `/\evil.com` variants) — logout links in the wild are trusted context, making phishing effective; token-in-URL flows would upgrade this to High.
- **Fix:** the exact-allowlist pattern already exists in this repo — `safe_counterexamples.py:10,20-24`:
  ```python
  ALLOWED_REDIRECTS = {"/dashboard", "/"}
  nxt = request.args.get("next", "/dashboard")
  if nxt not in ALLOWED_REDIRECTS: nxt = "/dashboard"
  return redirect(nxt)
  ```
  (exact set membership rejects absolute, protocol-relative, and `\/` tricks without string prefix-matching).
- **References:** CWE-601; `injection-flaws` open-redirect section; vuln-db CVE-2024-43796 (express sibling class — framework checks are not a substitute).

### SEC-004: No authentication/authorization layer on any route — HIGH
- **Where:** `app.py:12,19,26` (route census: 3/3 rows have no guard; no session/token/auth code in module)
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Evidence:** census of `@app.route` decorators vs middleware — zero guards; `rg -n -i "login|session|token|auth" app.py` → 0 hits.
- **Impact:** every handler — including the XML parsers (SEC-001/002) — is reachable anonymously. If these endpoints are meant to serve logged-in users, all severities above are "unauthenticated" in practice.
- **Fix:** add a `@require_auth` decorator (session or bearer token) on all three handlers before anything else; document the intended trust boundary in the route table.
- **Note:** if this service is deliberately public-facing (e.g., a webhook-style importer), downgrade to Medium and record the decision — the census requires an explicit trust model either way.

### SEC-005: No security headers; no rate limiting — MEDIUM (chain-critical)
- **Where:** `app.py` (global — no `after_request`/middleware registered; only `Flask(__name__)` at app.py:10)
- **CWE:** CWE-693 (Protection Mechanism Failure)
- **Evidence:** greps for `after_request|X-Frame|nosniff|CSP|limiter|rate` → 0 hits across the module.
- **Impact:** standalone: missing `X-Content-Type-Options`/`X-Frame-Options`/CSP is defense-in-depth debt. AS A CHAIN COMPONENT with SEC-002: nothing throttles or bounds the billion-laughs request — one client can cycle all workers. Tagged **chain-critical**.
- **Fix:** Flask-Talisman (headers+CSP) or explicit `after_request` header setter; Flask-Limiter (`@limiter.limit("10/minute")`) at minimum on `/import` and `/feed`; proxy-level request-size cap (e.g., 64KB) for XML bodies.

### SEC-006: Unpinned dependencies + no lockfile — supply-chain/reproducibility — HIGH
- **Where:** `requirements.txt:1-3`
- **CWE:** CWE-1104 / CWE-1357
- **Evidence:**
  ```text
  flask
  lxml
  defusedxml
  ```
  No version constraints, no lockfile, no hashes anywhere in the tree.
- **Impact:** every build resolves whatever the registry serves THAT DAY — a compromised/renamed transitive dep (or a malicious `lxml` sdist for the right platform) installs into prod. Live OSV check impossible (no lockfile = no resolvable versions) — this finding also blocks CVE scanning, so version risk is currently UNKNOWABLE.
- **Fix:** pin (`flask==3.0.*`, `lxml==5.*`, `defusedxml==0.7.*`), generate `requirements.lock`/`uv.lock` with hashes, commit it; then OSV/pip-audit becomes runnable in CI. `defusedxml` presence is good — see "What looks good".
- **References:** `dependency-vulns` Step 2 (no-lockfile → HIGH).

## What looks good
- `safe_counterexamples.py` demonstrates the correct fixes for every planted class: `defusedxml.ElementTree.fromstring` (blocks DTDs/entities), an EXACT-set redirect allowlist (survives `//evil.com` and absolute URLs), and a `parse_url_checked` helper that rejects scheme/netloc before path-joining. If these are the team's reference patterns, keep them linked in review docs.
- No secrets, no SQL surface, no debug mode, no template rendering, no crypto usage to misuse.

## Recommended fix order
1. **SEC-001** (critical, small: swap parser to defusedxml — already a dependency) →
2. **SEC-002** (same one-line class of fix) →
3. **SEC-006** (pin + lockfile; unblocks all future CVE scanning) →
4. **SEC-005** (limiter + size cap on the XML routes; completes the DoS defense) →
5. **SEC-004** (decide and enforce the trust model) →
6. **SEC-003** (copy the existing allowlist pattern)

## Coverage (OWASP completeness gate)
A01 SEC-004 · A02 not assessed (no crypto surface) · A03 SEC-001/002/003 · A04 rate-limit gap in SEC-005 · A05 SEC-005 · A06 SEC-006 (+live OSV not-run) · A07 SEC-004 · A08 no deserialization beyond XML (covered), supply chain in SEC-006 · A09 no logging of any kind — audit events cannot exist (folded into SEC-005 hardening; no auth surface to log) · A10 SSRF via XXE external entities (under SEC-001 impact).
