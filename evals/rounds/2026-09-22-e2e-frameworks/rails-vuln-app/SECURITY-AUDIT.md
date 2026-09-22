# Security Audit — rails-vuln-app
Date: 2026-09-22 | Scope: working tree | Auditor: security-skills v1.2.0-1-g9a3b7cd
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: NOT RUN (no network) — OSV.dev + CISA KEV + endoflife skipped

## Stack
Rails 5.2.3 monolith fixture (Devise 4.7.1 declared but no auth wiring, pg 1.1.4), cookie
session store (`_vuln_session`), one controller (UsersController) with 5 actions
(index/create/show/export/switch), ERB views, config/secrets.yml with a committed
production `secret_key_base`. No Gemfile.lock, no CI/infra files, no background jobs.
Repo size: tiny (~55 LOC) — full read.

## Summary
| Severity | Count |
|---|---|
| Critical | 3 |
| High | 6 |
| Medium | 3 |
| Low | 1 |

**Chains (4):**
- **A — Admin takeover, zero prerequisites:** SEC-005 (`permit!` mass assignment) sets
  `admin` via POST /users; SEC-004 (no auth at all) means no login needed; the JSON
  response reflects the new admin row back.
- **B — Session forgery:** SEC-010 (committed `secret_key_base`) + cookie_store lets an
  attacker forge a validly-signed `_vuln_session` cookie for any user — defeats any
  future authentication added on top.
- **C — Stored XSS:** SEC-005 writes attacker `bio` → SEC-002 renders it raw on /users/:id
  → stored XSS; SEC-003 (CSRF off) compounds session-riding impact.
- **D — Secret recovery loop:** SEC-006 (`send_file(params[:path])`) reads
  `config/secrets.yml` itself → recovers `secret_key_base` → feeds Chain B.

## Findings

### SEC-001: SQL injection via interpolated `where` — CRITICAL
- **Where:** `app/controllers/users_controller.rb:9`
- **CWE:** CWE-89 (SQL Injection)
- **Evidence:**
  ```ruby
  @users = User.where("name = '#{params[:name]}'")
  ```
- **Impact:** Unauthenticated arbitrary SQL (Rails 5.2 + PG): `' OR 1=1 --` dumps the
  users table; stacked/boolean/blind extraction of any data the DB user can read.
- **Fix:** `@users = User.where(name: params[:name])` (hash form), or
  `where("name = ?", params[:name])` (bound placeholder). Effort: S.
- **References:** OWASP A03

### SEC-002: Stored XSS — `raw` on model attribute — HIGH
- **Where:** `app/views/users/show.html.erb:2`
- **CWE:** CWE-79 (XSS)
- **Evidence:**
  ```erb
  <%= raw @user.bio %>          <%# SEC-02 %>
  ```
- **Impact:** `bio` is attacker-writable via SEC-005's create → `<script>` executes in
  every visitor's session on /users/:id (stored, not reflected).
- **Fix:** `<%= @user.bio %>` — ERB escapes by default; keep `raw` only for
  first-party-sanitized HTML. Effort: S.
- **References:** OWASP A03

### SEC-003: CSRF verification skipped controller-wide — HIGH
- **Where:** `app/controllers/users_controller.rb:4`
- **CWE:** CWE-352 (CSRF)
- **Evidence:**
  ```ruby
  skip_before_action :verify_authenticity_token
  ```
- **Impact:** All state-changing actions (create/export/switch) callable cross-site from
  any page the victim visits; once auth exists this becomes full account abuse.
- **Fix:** Remove the skip (webhook endpoints only, if ever); keep
  `protect_from_forgery with: :exception` in ApplicationController. Effort: S.

### SEC-004: No authentication/authorization on any action — HIGH
- **Where:** `app/controllers/users_controller.rb:5` (route census: index:7, create:12,
  show:19, export:23, switch:28 — 0/5 guarded)
- **CWE:** CWE-306 / CWE-639
- **Evidence:** No `before_action :authenticate_user!` (Devise present in Gemfile but
  unwired); `User.find(params[:id])` at :21 without ownership scoping.
- **Impact:** Unauthenticated listing, creation, file export, and method dispatch; the
  `find(params[:id])` is additionally IDOR-ready (sequential IDs) for when auth lands.
- **Fix:** `before_action :authenticate_user!` + `authorize_resource`-style checks;
  scope reads: `current_user.users.find(params[:id])`. Effort: S/M.

### SEC-005: Mass assignment — `permit!` opens every column — CRITICAL
- **Where:** `app/controllers/users_controller.rb:36` (used at :14-16)
- **CWE:** CWE-915 (Mass Assignment)
- **Evidence:**
  ```ruby
  params.require(:user).permit!
  ...
  user = User.new(user_params); user.save; render json: user
  ```
- **Impact:** Attacker POSTs `user[admin]=true` (or any column — `credits`, `role`);
  response confirms. Direct privilege escalation (Chain A).
- **Fix:** `params.require(:user).permit(:name, :email, :bio)`; never `permit!`. Effort: S.
- **References:** OWASP A01/A04

### SEC-006: Path traversal / arbitrary file read via `send_file` — HIGH
- **Where:** `app/controllers/users_controller.rb:25`
- **CWE:** CWE-22
- **Evidence:**
  ```ruby
  send_file(params[:path])
  ```
- **Impact:** `?path=../../config/secrets.yml` exfiltrates the Rails secret (Chain D);
  any file readable by the app process (env files, keys, /etc/passwd) is downloadable
  unauthenticated.
- **Fix:** Serve from an allowlisted dir with a contained, resolved path:
  `send_file(Rails.root.join('exports', basename).to_s, ...)` after
  `File.expand_path` containment check. Effort: S/M.

### SEC-007: Arbitrary method dispatch via `public_send(params[:method])` — HIGH
- **Where:** `app/controllers/users_controller.rb:30`
- **CWE:** CWE-470 (Unsafe Reflection)
- **Evidence:**
  ```ruby
  self.public_send(params[:method])
  ```
- **Impact:** Attacker invokes any public method on the controller instance (incl.
  framework-inherited ones) with full controller context — a gadget surface that turns
  any future dangerous method into an instant exploit primitive.
- **Fix:** Explicit allowlist map: `ACTIONS = {'activate' => :activate!}.freeze` with
  `send(ACTIONS[params[:method]] || :head_bad_request)`. Effort: S.

### SEC-008: `force_ssl = false` in production — MEDIUM
- **Where:** `app/environments/../config/environments/production.rb:3`
- **CWE:** CWE-319
- **Evidence:** `config.force_ssl = false`
- **Impact:** Session cookie and all data in cleartext; MITM reads/rewrites sessions
  (compounds SEC-009/SEC-010 chains).
- **Fix:** `config.force_ssl = true` (+ HSTS comes with it). Effort: S.

### SEC-009: Session cookie without `secure`/`same_site` flags — MEDIUM
- **Where:** `config/environments/production.rb:4`
- **CWE:** CWE-1004
- **Evidence:** `config.session_store :cookie_store, key: '_vuln_session'`
- **Impact:** Cookie travels over HTTP (SEC-008) and is sent on cross-site requests
  (compounds the missing CSRF defense).
- **Fix:** `:cookie_store, key: '_vuln_session', secure: true, same_site: :lax` (Rails
  6.1+ flag; on 5.2 set via middleware). Effort: S.

### SEC-010: Committed production `secret_key_base` — CRITICAL
- **Where:** `config/secrets.yml:2`
- **CWE:** CWE-798 (Hardcoded Credentials)
- **Evidence:**
  ```yaml
  production:
    secret_key_base: rails-fixture-secret-key-base-0000000000000000000000
  ```
- **Impact:** Anyone with repo access forges signed session cookies / decrypts
  encrypted cookie data for ANY user (Chain B) — full impersonation. (Value looks
  placeholder-like, but the finding is the committed production secret slot; rotate
  regardless.)
- **Fix:** Move to `ENV["SECRET_KEY_BASE"]` / Rails credentials + `config/master.key`
  (gitignored); rotate the leaked value and scrub history (`git filter-repo`). Removal
  from HEAD alone is NOT remediation. Effort: M.

### SEC-011: No lockfile (no Gemfile.lock) — HIGH
- **Where:** `Gemfile` (repo tree — no Gemfile.lock present)
- **CWE:** CWE-1104
- **Evidence:** `rg --files -g 'Gemfile.lock'` → 0 results for a manifest declaring
  rails 5.2.3, devise 4.7.1, pg 1.1.4.
- **Impact:** Non-reproducible builds; a malicious/renamed transitive gem resolves at
  install time (supply-chain swap).
- **Fix:** Commit `Gemfile.lock` (deploy artifacts), run `bundle install --deployment`. Effort: S.

### SEC-012: `render json: user` over-returns full model — MEDIUM (Possible — needs verification)
- **Where:** `app/controllers/users_controller.rb:16`
- **CWE:** CWE-200
- **Evidence:** `render json: user` returns every column of the just-created user.
- **Impact:** If the model carries `password_digest`/tokens (schema not in repo),
  creation responses leak them; with `permit!` every column is attacker-writable AND
  echoed back. Verify against `db/schema.rb`.
- **Fix:** Explicit serializer / `as_json(only: [...])` allowlist. Effort: S.

### SEC-013: Stale, likely-vulnerable stack (unverified — no network) — LOW
- **Where:** `Gemfile:3-5`
- **CWE:** CWE-1104
- **Evidence:** rails 5.2.3 (2019; 5.2 line is EOL), devise 4.7.1, pg 1.1.4.
- **Impact:** Rails 5.2.x has multiple known CVEs fixed only in later 5.2.x/6.x
  patches (e.g., the CVE-2019-5418 render-file family); 5.2 no longer receives
  security fixes at all.
- **Fix:** Upgrade to a supported Rails (7.x), then re-run OSV/live checks (skipped
  here — no network). Effort: L.

## What looks good
- `<%= @user.name %>` (show.html.erb:3) — escaped counterpart, ERB auto-escaping used
- Strong-params structure exists (`params.require(:user)`) — only the `permit!` is wrong
- No `Marshal.load` / `Oj.load` / unsafe `YAML.load` anywhere
- No `redirect_to(params[...])` (open redirect) sinks
- No command-execution sinks (`system`, backticks) in first-party code
- No inline secrets beyond the secrets.yml slot; no keys/tokens in controllers/views

## OWASP completeness gate
A01 covered (SEC-004/005/007) · A02 covered (SEC-010) · A03 covered (SEC-001/002/006)
· A04 partial (no rate limiting — trivial surface, noted) · A05 covered (SEC-008/009)
· A06 covered w/o live data (SEC-011/013 — OSV not run) · A07 covered (SEC-003/004/010)
· A08 covered (SEC-011 supply-chain side; no deserialization sinks present)
· A09 partial (no auth events to log — see SEC-004; logging not assessable, fixture has
none) · A10 n/a (no outbound fetch sinks).

## Recommended fix order
1. SEC-010 rotate + scrub secret_key_base (critical, S) — unblocks trust in sessions
2. SEC-004 add authenticate before_action (high, S)
3. SEC-005 permit allowlist (critical, S)
4. SEC-001 hash-form where (critical, S)
5. SEC-002 drop `raw` (high, S)
6. SEC-006/007 allowlist send_file + dispatch map (high, S/M)
7. SEC-003 restore CSRF (high, S)
8. SEC-008/009 TLS + cookie flags (medium, S)
9. SEC-011 lockfile, SEC-013 upgrade path (high/low, S→L)
