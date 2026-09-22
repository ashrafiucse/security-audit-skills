# Security Audit — laravel-vuln-app
Date: 2026-09-22 | Scope: working tree | Auditor: security-skills v1.2.0-1-g9a3b7cd
Knowledge base: 33 vuln-db entries (newest 2026-09-11) | Live checks: NOT RUN (offline round)

## Stack
Laravel 8.83.1 / PHP ^8.0, MySQL, session/cookie auth implied (no auth wiring present). 8 first-party files: routes, one model, two controllers/middleware, one Blade view, committed `.env`. No infra/CI files.

## Summary
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 6 |
| Medium | 3 |

**Attack chains (2 critical):**
- **CHAIN-1: path traversal → APP_KEY → RCE.** SEC-006 (`GET /download?path=../../.env`) reads the project root `.env` → SEC-001 APP_KEY → forge Laravel encrypted cookies/session payloads → classic Laravel unserialization RCE chain.
- **CHAIN-2: unauthenticated admin takeover.** SEC-005 (no auth middleware on any route) + SEC-003 (mass assignment via `$guarded = []`) → `POST /users` with `is_admin=1` → admin at `/admin/users`.

## Findings

### SEC-001: Committed APP_KEY — CRITICAL
- **Where:** `.env:3`
- **CWE:** CWE-798 (Hardcoded Credentials)
- **Evidence:**
  ```dotenv
  APP_ENV=production
  APP_KEY=base64:RmFrZUtleUZvckV2YWxGaXh0dXJlMDA=
  ```
- **Impact:** Leaked APP_KEY lets an attacker forge encrypted cookies and tamper with serialized session/job payloads — chains to RCE via PHP deserialization gadgets. All session data must be treated as compromised.
- **Fix:** `php artisan key:generate` (rotate), remove `.env` from the tree + history (`git filter-repo`), move to secret injection at deploy time.

### SEC-002: Database password committed — HIGH
- **Where:** `.env:8`
- **CWE:** CWE-798
- **Evidence:** `DB_PASSWORD=laravel-prod-pass-2026` (prod-labelled value; host is 127.0.0.1 which lowers exposure)
- **Impact:** DB credential disclosure to anyone with repo access; rotation debt.
- **Fix:** rotate the credential; inject via env/secret manager, never commit.

### SEC-003: Mass assignment — explicit wide-open guard — CRITICAL
- **Where:** `app/Models/User.php:10` + `app/Http/Controllers/UserController.php:14`
- **CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
- **Evidence:**
  ```php
  protected $guarded = [];          // User.php:10 — every column assignable
  $user = User::create($request->all());   // UserController.php:14 — unauthenticated POST /users
  ```
- **Impact:** Attacker self-promotes by adding `is_admin=1`/`role=admin` to the registration POST. Likelihood: unauthenticated, trivial.
- **Fix:** `protected $fillable = ['name', 'email', 'password'];` + FormRequest validation with an explicit field allowlist.

### SEC-004: SQL injection via DB::raw concatenation — CRITICAL
- **Where:** `app/Http/Controllers/UserController.php:21-23`
- **CWE:** CWE-89
- **Evidence:**
  ```php
  return DB::select(DB::raw(
      "SELECT * FROM users WHERE name = '" . $request->input('name') . "'"
  ));
  ```
- **Impact:** Unauthenticated SQLi (`GET /users/search?name=' OR 1=1--`): full table dump incl. credential hashes.
- **Fix:** `User::where('name', $request->input('name'))->get()` or `DB::select("... WHERE name = ?", [$name])`.

### SEC-005: No authentication on any route (route census) — HIGH
- **Where:** `routes/web.php:8-11`
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Evidence:** census table — 4/4 routes carry no middleware:
  ```php
  Route::get('/admin/users', [AdminController::class, 'index']);   // :8 admin listing
  Route::post('/users', [UserController::class, 'store']);          // :9 state-changing
  Route::get('/users/search', ...); Route::get('/download', ...);   // :10-11
  ```
- **Impact:** Admin listing + user creation + file download all reachable unauthenticated. Note: `AdminController` does not exist in the tree (route 500s as-is) — but the route map shows zero auth wiring anywhere.
- **Fix:** `Route::middleware('auth')->group(...)`; admin routes behind `auth` + `can:` policy checks.

### SEC-006: Path traversal in file download — HIGH
- **Where:** `app/Http/Controllers/UserController.php:29`
- **CWE:** CWE-22
- **Evidence:**
  ```php
  return response()->download(storage_path('app/' . $request->input('path')));
  ```
- **Impact:** `?path=../../.env` exfiltrates any readable project file (feeds CHAIN-1).
- **Fix:** allowlist + containment: `Storage::disk('local')->download($validated)` with `realpath` prefix check, or `return response()->download($request->input('path'))` replaced by named-file lookup.

### SEC-007: CSRF protection globally disabled — HIGH
- **Where:** `app/Http/Middleware/VerifyCsrfToken.php:10-12`
- **CWE:** CWE-352
- **Evidence:**
  ```php
  protected $except = [ '*' ];
  ```
- **Impact:** Every state-changing endpoint (user creation) is CSRF-able by any third-party page once sessions exist.
- **Fix:** remove the wildcard; if a webhook needs exemption, exempt that exact path only.

### SEC-008: Blade raw output XSS — HIGH
- **Where:** `resources/views/greeting.blade.php:3`
- **CWE:** CWE-79
- **Evidence:**
  ```blade
  <h1>Hello {!! $name !!}</h1>
  ```
- **Impact:** Raw sink bypasses Blade escaping → stored/reflected XSS when rendered. Likelihood note: no route in this fixture currently renders the view — report as latent sink; fix regardless (dead views get wired up later).
- **Fix:** `{{ $name }}`.

### SEC-009: APP_DEBUG=true with APP_ENV=production — HIGH
- **Where:** `.env:2,4`
- **CWE:** CWE-489 (Active Debug Code)
- **Evidence:** `APP_ENV=production` + `APP_DEBUG=true`
- **Impact:** Verbose stack traces leak paths, config, and historically `.env` contents via error pages (Ignition-era Laravel RCE family). Compounded by SEC-010.
- **Fix:** `APP_DEBUG=false` in production.

### SEC-010: Debug toolbar in production dependencies — MEDIUM
- **Where:** `composer.json:7`
- **CWE:** CWE-489
- **Evidence:** `"barryvdh/laravel-debugbar": "3.6.2"` under `require` (not `require-dev`)
- **Impact:** Debug panel renders queries/config in prod responses when enabled.
- **Fix:** move to `require-dev`.

### SEC-011: No composer.lock — supply-chain/reproducibility — HIGH
- **Where:** `composer.json` (no lockfile in tree)
- **CWE:** CWE-1104
- **Evidence:** `ls composer.lock` → absent; `laravel/framework: 8.83.1` pinned
- **Impact:** Non-reproducible installs (a malicious/renamed transitive dep can slip in). Laravel 8 is EOL — no security fixes upstream (live OSV check not run, offline round).
- **Fix:** commit `composer.lock`; plan upgrade to a supported Laravel line.

### SEC-012: Over-returning endpoints — MEDIUM
- **Where:** `app/Http/Controllers/UserController.php:15,22` (+ no `$hidden` on `app/Models/User.php`)
- **CWE:** CWE-200
- **Evidence:** `return response()->json($user);` and `SELECT * FROM users` — model has no `$hidden`, so serialized output includes every column.
- **Impact:** Credential hashes/PII leak through API responses as schema grows.
- **Fix:** `protected $hidden = ['password', 'remember_token'];` + explicit response DTOs + column allowlist in selects.

### SEC-013: No security logging / no rate limiting — MEDIUM
- **Where:** `app/` + `routes/` (absence — grep `Log::|logger|report(` → 0 hits)
- **CWE:** CWE-778
- **Impact:** No audit events for user creation/admin actions; brute-force/SQLi enumeration unhindered (A04: no rate limits on `/users/search`).
- **Fix:** log auth + state changes with actor; throttle `search`/`store` (`throttle:60,1`).

## OWASP gate
A01 ✓ (003,005) · A02 ✓ (001,002) · A03 ✓ (004,006,008) · A04 partial (013) · A05 ✓ (009,010; headers/cookie config absent → not assessed) · A06 ✓ (011; live OSV not run) · A07 ✓ (005,007 — no authn layer at all) · A08 ✓ (011) · A09 ✓ (013) · A10 n/a (no outbound fetch).

## What looks good
- Blade `{{ $name }}` on the comparison line — correct default escaping (greeting.blade.php:4)
- No `unserialize`/`eval`/`assert` in first-party code
- Query builder not misused beyond SEC-004; no `$where`-style NoSQL
- CSRF middleware class present (just misconfigured — easy revert)

## Recommended fix order
1. SEC-001 rotate APP_KEY + purge .env (S) → breaks CHAIN-1 even before SEC-006 fix
2. SEC-003 fillable allowlist (S) + SEC-005 auth middleware (S) → kills CHAIN-2
3. SEC-004 parameterize (S), SEC-006 contained download (S)
4. SEC-009/010 debug off + debugbar to dev (S)
5. SEC-007 CSRF re-enable (S), SEC-002 rotate DB password (S)
6. SEC-011 lockfile + upgrade plan (M), SEC-008 raw echo (S), SEC-012 hidden fields (S), SEC-013 logging+throttle (M)
