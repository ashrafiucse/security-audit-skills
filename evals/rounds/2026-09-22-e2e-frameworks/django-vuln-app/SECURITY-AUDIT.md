# Security Audit — django-vuln-app
Date: 2026-09-22 | Scope: working tree (fixture snapshot at skills-repo commit 9a3b7cd) | Auditor: security-skills v1.2.0-1-g9a3b7cd
Knowledge base: 33 vuln-db entries (newest 2026-09-11) | Live checks: NOT RUN (offline) — local vuln-db consulted; OSV/KEV/endoflife skipped

## Stack
Django 2.2.0 + djangorestframework 3.9.1 (requirements.txt, `==`-pinned, no hashes). Three function views (`search`, `greet`, `invoice`), one ModelForm, one template. **No auth layer anywhere** (no `login_required`/`LoginRequiredMixin` hits; census: 3/3 handlers unguarded). No `urls.py` in tree (routing not shipped — reachability assumed for all three handlers). No infra files, no logging, no file handling, no crypto usage beyond settings.

## Summary
| Severity | Count |
|---|---|
| Critical | 1 |
| High | 8 |
| Medium | 2 |
| Low | 1 |

**Attack chains (3):**
1. **SEC-006 SECRET_KEY → session/token forgery** — hardcoded key signs Django sessions, CSRF tokens and password-reset tokens → offline forgery = auth bypass on any deployment using this key.
2. **SEC-004 IDOR + raw HTML render** — unauthenticated `invoice/<id>` reads any invoice, and `HttpResponse` serves `note` as `text/html` → cross-user data theft doubles as a stored-XSS delivery path (note content rendered in an admin's browser).
3. **SEC-009 ALLOWED_HOSTS='\*' + password-reset poisoning** — wildcard hosts enable Host-header control of reset links (CVE-2016-2518 family); conditional on a reset flow existing (`contrib.auth` unused in tree → marked *possible*).

## Findings

### SEC-001: SQL injection via f-string into `objects.raw()` — CRITICAL
- **Where:** `myapp/views.py:9-11`
- **CWE:** CWE-89
- **Evidence:**
  ```python
  rows = Invoice.objects.raw(
      f"SELECT * FROM myapp_invoice WHERE note = '{request.GET.get('q')}'"
  )
  ```
- **Impact:** Unauthenticated `?q='` breaks out of the literal → arbitrary SQL against the invoices table (UNION reads, and on Postgres multi-statement via driver-dependent batching). Reachable: no auth on `search`.
- **Fix:** ORM lookup or parameterized raw: `Invoice.objects.raw("SELECT * FROM myapp_invoice WHERE note = %s", [request.GET.get('q')])` — better: `Invoice.objects.filter(note=q)`.
- **References:** OWASP A03; django-security Step 2.

### SEC-002: Reflected XSS — `mark_safe` on request data — HIGH
- **Where:** `myapp/views.py:17`
- **CWE:** CWE-79
- **Evidence:** `return HttpResponse(mark_safe(request.GET.get('name', '')))`
- **Impact:** `?name=<script>...` executes in any visitor's browser — session theft, phishing. Compounded by SEC-010 (no Secure cookie flags) and no CSP.
- **Fix:** Drop `mark_safe`; render via template with autoescaping, or escape explicitly.

### SEC-003: Template XSS bypass — `{{ name|safe }}` — HIGH
- **Where:** `myapp/templates/greet.html:2`
- **CWE:** CWE-79
- **Evidence:** `<h1>Hello {{ name|safe }}</h1>`
- **Impact:** Same class as SEC-002 via the template path — the `|safe` filter disables Jinja/Django autoescaping for a user-derived variable.
- **Fix:** Remove the `|safe` filter; the adjacent `{{ count }}` on line 3 is the correct pattern.

### SEC-004: IDOR — invoice fetched by pk, no ownership check — HIGH
- **Where:** `myapp/views.py:20-22`
- **CWE:** CWE-639 / CWE-862
- **Evidence:** `return HttpResponse(Invoice.objects.get(pk=invoice_id).note)`
- **Impact:** Unauthenticated enumeration of every invoice (`/invoice/1..n`) — financial data disclosure; `note` served as `text/html` (views.py:12 pattern) makes victim-side rendering a stored-XSS vector (see chain 2). Sequential integer pks (implied by `pk=`) ease scraping.
- **Fix:** Scope the query to the owner (`Invoice.objects.get(pk=invoice_id, owner=request.user)`) + `@login_required`; return `application/json` or escape.
- **Likelihood:** unauthenticated; **Effort:** S.

### SEC-005: Mass assignment — `fields = '__all__'` on UserProfileForm — HIGH
- **Where:** `myapp/forms.py:9-10`
- **CWE:** CWE-915
- **Evidence:**
  ```python
  class Meta:
      model = UserProfile
      fields = '__all__'   # includes is_premium and role
  ```
- **Impact:** Any view binding `request.POST` to this form lets users set `role`/`is_premium` → privilege/billing escalation. Precondition noted: no view in this tree binds the form yet — the trap is armed for the first caller.
- **Fix:** `fields = ['display_name', 'email']` (explicit allowlist).
- **Likelihood:** requires a binding view; **Effort:** S.

### SEC-006: Hardcoded `SECRET_KEY` (dev-prefix format) — HIGH
- **Where:** `myapp/settings.py:2`
- **CWE:** CWE-798
- **Evidence:** `SECRET_KEY = 'django-insecure-fixture-key-0f4t8w2qbkx3'`
- **Impact:** Signs sessions, CSRF tokens, password-reset tokens, and signed cookies. Disclosure → forge any session (chain 1). The `django-insecure-` prefix is the generated *dev* key format — a strong signal a dev key shipped to prod config.
- **Fix:** `SECRET_KEY = os.environ['DJANGO_SECRET_KEY']`; rotate the exposed value (rotation invalidates sessions — correct behavior).
- **Note:** regex secrets scan missed this token (pattern gap: `SECRET_KEY` name not covered); caught via django-security Step 1 — reported on skill-specified evidence.

### SEC-007: Hardcoded database password — HIGH
- **Where:** `myapp/settings.py:14`
- **CWE:** CWE-798
- **Evidence:** `'PASSWORD': 'django-prod-pass-2026',`
- **Impact:** DB credentials in source control; prod-looking value (name says prod). Anyone with repo read → DB access if the host/user pair is real.
- **Fix:** Env var / secret manager; rotate the credential (removing the line is not remediation if history/deploys retain it).

### SEC-008: `DEBUG = True` — HIGH
- **Where:** `myapp/settings.py:4`
- **CWE:** CWE-489
- **Evidence:** `DEBUG = True`
- **Impact:** Verbose error pages leak settings fragments, SQL, paths; historically settings/SECRET disclosure on crafted exceptions; amplifies SEC-001 (error-driven blind SQLi reads).
- **Fix:** `DEBUG = False` in prod settings; gate on env (`DEBUG = os.getenv('DJANGO_DEBUG') == '1'`).

### SEC-009: `ALLOWED_HOSTS = ['*']` — MEDIUM
- **Where:** `myapp/settings.py:5`
- **CWE:** CWE-16
- **Evidence:** `ALLOWED_HOSTS = ['*']`
- **Impact:** Accepts any Host header → host-header poisoning of absolute URLs (password-reset links — chain 3), cache poisoning behind proxies.
- **Fix:** `ALLOWED_HOSTS = ['app.example.com']` (explicit list).

### SEC-010: Insecure cookie flags — MEDIUM
- **Where:** `myapp/settings.py:7-8`
- **CWE:** CWE-614
- **Evidence:** `CSRF_COOKIE_SECURE = False` / `SESSION_COOKIE_SECURE = False`
- **Impact:** Session and CSRF cookies sent over plain HTTP → interception on hostile networks; pairs with SEC-002 (stolen cookies usable).
- **Fix:** Both `True` + `SESSION_COOKIE_SAMESITE = 'Lax'` + `SECURE_SSL_REDIRECT = True`.

### SEC-011: Known CVE in pinned Django + EOL runtime — HIGH
- **Where:** `requirements.txt:1`
- **CWE:** CWE-1104
- **Evidence:** `Django==2.2.0`
- **Impact:** Local knowledge base: **CVE-2019-19844** (password-reset account enumeration / reset-to-attacker) affects Django ≥2.2, <2.2.9 — 2.2.0 is in range. Django 2.2 reached EOL 2020-04: **no security fixes ever again** for any of the dozens of post-2020 Django CVEs. djangorestframework 3.9.1 (2019-era, same EOL class). Live OSV check not run (offline) — treat as the floor, not the ceiling.
- **Fix:** Upgrade to a supported Django LTS (≥4.2 latest patch, ≥5.x) + matching DRF; migration required (2.2→4.2 has breaking changes).
- **References:** CVE-2019-19844 (vuln-db 2019-12-18 entry); OWASP A06.

### SEC-012: No hash-pinned lockfile — LOW
- **Where:** `requirements.txt:1-2`
- **CWE:** CWE-1357
- **Evidence:** `==`-pinned but no hashes, no `requirements.txt` verification on install (`pip install --require-hashes` impossible).
- **Impact:** A compromised mirror/registry can swap the exact versions at build time.
- **Fix:** `pip-compile --generate-hashes` (pip-tools) and install with `--require-hashes`.

## What looks good
- ORM used as the default data path; `raw()` appears exactly once (single place to fix).
- DRF present but no permissive `DEFAULT_PERMISSION_CLASSES`/CORS config in settings (nothing over-open configured).
- No dangerous `eval`/`exec`/`pickle` usage (Step 6 clean); no file-upload surface.
- Templates use autoescaping by default (the one `|safe` is the exception, flagged).

## OWASP completeness gate
A01 broken access control — SEC-004, SEC-005 · A02 crypto failures — SEC-006, SEC-007, SEC-010 · A03 injection — SEC-001–003 · A04 insecure design — **not assessed** (no business flows to reason about) · A05 misconfig — SEC-008–010 · A06 vulnerable components — SEC-011, SEC-012 · A07 auth failures — no auth code present (finding in itself: census shows 0/3 guarded) · A08 integrity — SEC-012 · A09 logging — no logging at all → **not assessed** (noted: zero audit events exist if this went to prod) · A10 SSRF — no outbound HTTP calls (clean).

## Recommended fix order
1. SEC-001 (critical, S) — parameterize today.
2. SEC-006 + SEC-007 (rotate + env, S) — rotation first.
3. SEC-004 (S: ownership scope + login_required).
4. SEC-011 (L: Django LTS upgrade — schedule; interim WAF/patch-pin).
5. SEC-002/003/005/008/009/010 (S each — one settings+view sweep).
6. SEC-012 (S: hash pinning).
