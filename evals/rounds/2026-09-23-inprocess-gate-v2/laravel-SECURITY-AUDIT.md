# Security Audit — laravel-vuln-app
Date: 2026-09-23 | Scope: working tree (fixture) | Auditor: security-skills dev (IN-PROCESS run — see scoreboard label)
Knowledge base: 50 vuln-db entries (newest 2026-09-11) | Live checks: OSV.dev + CISA KEV

## Stack
Laravel 8.83.1 / PHP ^8.0 (composer.json; no lockfile). Entry: routes/web.php (UserController, AdminController).
Actors (Phase 0 census): anonymous (no middleware on any route), student/review-author (CourseReviewRequest), staff/moderator (reviews views), admin (AdminController, ungated). Surfaces: user store/search/download, admin users panel, greeting view, review moderation queue (list + detail), review write path, React admin dashboard (resources/js).

## Summary
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 6 |
| Medium | 1 |
| Low | 0 |

## Findings
### SEC-001: Committed `.env` with APP_KEY (cookie-forgery → deserialization RCE chain) — CRITICAL
- **Where:** `.env:3`
- **CWE:** CWE-798
- **Evidence:** `APP_KEY=base64:RmFrZUtleUZvckV2YWxGaXh0dXJlMDA=`
- **Impact:** forge encrypted cookies; with older serializable-session/queued-job payloads chains to RCE.
- **Fix:** rotate APP_KEY, purge from history, treat sessions as compromised.

### SEC-001b: DB_PASSWORD committed — HIGH
- **Where:** `.env:8` — **CWE-798** — `DB_PASSWORD=laravel-prod-pass-2026` — rotate + purge history.

### SEC-002: APP_DEBUG=true in production — HIGH
- **Where:** `.env:4` — stack traces; historic .env disclosure via error pages.

### SEC-003: Mass assignment — `$guarded = []` + `User::create($request->all())` — CRITICAL
- **Where:** `app/Models/User.php:10`, `app/Http/Controllers/UserController.php:14`
- **CWE:** CWE-915 — attacker self-promotes with `is_admin=1` in the POST.
- **Fix:** explicit `$fillable` + typed FormRequest.

### SEC-004: SQL injection via DB::raw concatenation — CRITICAL
- **Where:** `app/Http/Controllers/UserController.php:21-23` — **CWE-89** — `'... WHERE name = ''' . $request->input('name')` — use bindings `whereRaw('name = ?', [$name])`.

### SEC-005: Path traversal in download — HIGH
- **Where:** `app/Http/Controllers/UserController.php:29` — **CWE-22** — `storage_path('app/' . $request->input('path'))` — allowlist/basepath-check.

### SEC-006: Admin/state routes without auth middleware — HIGH
- **Where:** `routes/web.php:8-11` — **CWE-862** — `/admin/users`, POST /users etc. with no `auth` middleware.

### SEC-007: CSRF disabled globally — HIGH
- **Where:** `app/Http/Middleware/VerifyCsrfToken.php:10-12` — **CWE-352** — `$except = ['*']`.

### SEC-008: Blade raw output `{!! $name !!}` — HIGH
- **Where:** `resources/views/greeting.blade.php:3` — **CWE-79** — raw echo of a variable; `{{ $name }}` on :4 is the escaped counterpart.

### SEC-009: debugbar in production require — MEDIUM
- **Where:** `composer.json:7` — move to require-dev or remove.

### SEC-010: No composer.lock — HIGH (file-level anchor)
- **Where:** `composer.json:-` — non-reproducible installs; transitive-swap risk.

### SEC-011: Moderation-queue XSS → admin account takeover — CRITICAL (chain-critical)
- **Where:** `app/Http/Requests/CourseReviewRequest.php:14`, `app/Actions/CreateCourseReviewAction.php:17`, `resources/views/course-edit/reviews/view.blade.php:6`
- **CWE:** CWE-79 (stored) + CWE-269 (privilege direction)
- **Evidence:** `'body' => ['required', 'string', 'min:10']` (raw HTML accepted) → `$review->body = $request->validated('body');` (no purification) → `{!! nl2br($review->body) !!}` in the STAFF detail view (`nl2br` is NOT an escape; `{!! !!}` bypasses Blade escaping).
- **Impact:** student-authored payload fires in the admin origin; pending-moderation status guarantees a privileged viewer opens it → session-riding → role elevation. Privilege direction: unprivileged author → privileged viewer = Critical.
- **Fix:** `{!! nl2br(e($review->body)) !!}` in every staff view (list AND detail — list `index.blade.php:7` already escapes via `{{ }}`), or a Purify cast on the model.

## What looks good
- `{{ $name }}` / `{{ $review->body }}` escaped renders (greeting:4, index:7); `nl2br(e(...))` in safe-detail-view:4; rating rule is typed (`integer, between:1,5`).

## Coverage matrix (actor × surface — from the Phase 0 census)
| Surface ↓ · Actor → | anonymous | student/reviewer | staff/mod | admin |
|---|---|---|---|---|
| User store/search/download | ✅ SEC-003/004/005/006 | n/a | n/a | n/a |
| Admin users panel | ✅ SEC-006 (no guard) | n/a | n/a | n/a |
| Greeting view | ✅ SEC-008 | n/a | n/a | n/a |
| Review write path | n/a | ✅ SEC-011 (write half) | n/a | n/a |
| Moderation list view | n/a | n/a | 🟢 escaped `{{ }}` (index:7) | n/a |
| Moderation detail view | n/a | n/a | ✅ SEC-011 (render half) | n/a |
| React admin dashboard | n/a | n/a | n/a | 🟢 JSX `!!` noise, no HTML injection sink (AdminDashboard.tsx:5 aria-invalid only) |

## Not assessed
- AdminController implementation (referenced in routes, file absent from fixture) — would close by auditing the real controller.

## Census receipts
| Census | hits | dispositioned |
|---|---|---|
| Blade raw echoes (glob *.blade.php) | 5 | 5 |
| (unglobbed raw-echo scan for noise demo) | 11 | excluded by glob — React/TSX noise, not Blade |

Dispositions: greeting:2 comment ✅safe · greeting:3 SEC-008 · safe-detail-view:4 verified-safe (e() inside) · view:2 comment ✅safe · view:6 SEC-011.

## Recommended fix order
1. SEC-001 rotate APP_KEY + purge (S) → 2. SEC-011 escape staff renders (S) → 3. SEC-004 bindings (S) → 4. SEC-003 fillable (S) → 5. SEC-007/006 middleware (M) → 6. SEC-005, SEC-002, SEC-010 (M).
