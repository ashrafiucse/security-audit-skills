# Security Audit — laravel-vuln-app (incident-conversion round)
Date: 2026-09-23 | Scope: working tree (fixture) | Auditor: security-skills dev (IN-PROCESS run — ground-truth-aware artifact validation, not blind recall; see scoreboard label)
Trigger: user-reported incident — trial-tenant mass-email blast (~1200 emails in 2 minutes). This round adds Step 8 coverage (feature-flag gating, outbound-email amplification) + flow-security F9.

## Stack
Laravel 8.83.1 / PHP ^8.0 (composer.json; no lockfile). Core app: routes/web.php, UserController. Marketing module: modules/marketing (LeadController, jobs, providers, routes). Actors: anonymous, student/reviewer, staff/mod, admin, **trial-tenant admin (plan-constrained — the incident persona: authenticated AND privileged, stopped only by the plan)**. Surfaces: user CRUD/download, admin panel, review moderation (list/detail/mail/grading), marketing email compose + blast pipeline + public lead endpoints, deploy scripts.

## Summary
| Severity | Count |
|---|---|
| Critical | 9 |
| High | 10 |
| Medium | 2 |
| Low | 0 |

## Findings
### SEC-001: Committed `.env` with APP_KEY (cookie-forgery → deserialization RCE chain) — CRITICAL
- **Where:** `.env:3` — **CWE-798** — `APP_KEY=base64:RmFrZUtleUZvckV2YWxGaXh0dXJlMDA=` — rotate + purge history.

### SEC-001b: DB_PASSWORD committed — HIGH
- **Where:** `.env:8` — **CWE-798** — `DB_PASSWORD=laravel-prod-pass-2026` (documented fake; pattern is the finding).

### SEC-002: APP_DEBUG=true in production — HIGH
- **Where:** `.env:4` — **CWE-200** — stack traces via error pages.

### SEC-003: Mass assignment — `$guarded = []` + `User::create($request->all())` — CRITICAL
- **Where:** `app/Models/User.php:10`, `app/Http/Controllers/UserController.php:14` — **CWE-915** — `is_admin=1` self-promotion.

### SEC-004: SQL injection via DB::raw concatenation — CRITICAL
- **Where:** `app/Http/Controllers/UserController.php:21-23` — **CWE-89** — use bindings.

### SEC-005: Path traversal in download — HIGH
- **Where:** `app/Http/Controllers/UserController.php:29` — **CWE-22**.

### SEC-006: Admin/state routes without auth middleware — HIGH
- **Where:** `routes/web.php:8-11` — **CWE-862**.

### SEC-007: CSRF disabled globally — HIGH
- **Where:** `app/Http/Middleware/VerifyCsrfToken.php:10-12` — **CWE-352** — `$except = ['*']`.

### SEC-008: Blade raw output `{!! $name !!}` — HIGH
- **Where:** `resources/views/greeting.blade.php:3` — **CWE-79** — `{{ $name }}` :4 is the escaped counterpart.

### SEC-009: debugbar in production require — MEDIUM
- **Where:** `composer.json:7`.

### SEC-010: No composer.lock — HIGH (file-level anchor)
- **Where:** `composer.json:-` — non-reproducible installs.

### SEC-011: Moderation-queue XSS → admin account takeover — CRITICAL (chain-critical)
- **Where:** `app/Http/Requests/CourseReviewRequest.php:14`, `app/Actions/CreateCourseReviewAction.php:17`, `resources/views/course-edit/reviews/view.blade.php:6`
- **CWE:** CWE-79 (stored) + CWE-269 — raw-HTML acceptance → unpurified store → `{!! nl2br($review->body) !!}` in the staff detail view; privilege direction unprivileged→privileged = Critical.

### SEC-012: Support/mail channel XSS — CRITICAL
- **Where:** `resources/views/mail/support-ticket.blade.php:6` — **CWE-79** — student message raw-rendered in the staff HTML mail view; fires in webmail previews. Safe counterpart: `mail/safe-support-ticket.blade.php:6`.

### SEC-013: Grading channel XSS — CRITICAL
- **Where:** `resources/views/course-edit/quiz/grade.blade.php:5` — **CWE-79** — answer raw-rendered in the grader view; grading forces staff to open every pending answer. Safe counterpart: `quiz/safe-grade.blade.php:4` (escape-then-format).

### SEC-014: Feature-flag default-true for a dangerous capability — HIGH
- **Where:** `modules/marketing/src/Providers/MarketingServiceProvider.php:17` — **CWE-1188** — `Feature::define('import-leads', true)` — global enable, no per-plan constraint (the incident's import enabler). Safe shape: plan closure (`SafeMarketingServiceProvider.php:18`).

### SEC-015: Flag gated in UI/job only — compose route has auth but NO feature middleware, NO throttle — CRITICAL
- **Where:** `modules/marketing/routes/web.php:8-9` — **CWE-284/863** — the route is the enforcement point; menu hiding is cosmetic. Safe counterpart: `safe-web.php:7-8` (`feature:send-email` + `throttle:blast-compose`).

### SEC-016: Outbound-message amplification (F9) — one request → N emails — CRITICAL
- **Where:** `modules/marketing/src/Jobs/ProcessEmailBlast.php:10-19` — **CWE-406/770** — `Lead::query()->get()` unbounded → per-row recipient + queued mail job; no cap, no quota, no throttle. One HTTP request = whole mailing list. Safe counterpart: `SafeProcessEmailBlast.php` (atomic quota + verified-only + `limit(500)`).

### SEC-017: `send-email` gate lives ONLY inside the queued job — HIGH
- **Where:** `modules/marketing/src/Jobs/SendEmailToEmailBlastRecipient.php:13` — defense-in-depth deployed as the only gate (evidence half of the SEC-015 chain).

### SEC-018: Public GET with side effect — send-verification-link — CRITICAL
- **Where:** `modules/marketing/routes/web.php:12` — **CWE-352/1284** — no auth, no throttle, non-idempotent GET; ID enumeration = mail bomb with zero auth and zero flags. Safe counterpart: `safe-web.php:11-12` (POST + signed + `throttle:6,1`).

### SEC-019: Public subscribe POST — no FormRequest/throttle/captcha — HIGH
- **Where:** `modules/marketing/routes/api.php:7` — **CWE-799** — email-triggering public endpoint.

### SEC-020: `$request->all()` into compose DTO — HIGH
- **Where:** `modules/marketing/src/Http/Controllers/LeadController.php:13` — **CWE-915** — attacker-controlled subject/body = phishing from the platform's own domain. Safe counterpart: `SafeLeadController.php` (ComposeEmailRequest + `validated()`).

### SEC-021: Pennant database store + no purge in deploy — MEDIUM (file-level anchor)
- **Where:** `config/pennant.php:6`, `deploy/deploy.sh:-` — **CWE-672** — stored per-scope values survive flag-default reverts; any tenant resolved during a true-default window keeps `true` until purged. Safe counterpart: `deploy/safe-deploy.sh:8` (`pennant:purge`).

## Must NOT trigger (verified clean)
`{{ }}` escaped renders; `nl2br(e(...))` forms; JSX `!!` noise (not Blade); safe-web routes carry feature+throttle middleware; Safe* provider/controller/job use plan closures, FormRequest, atomic quota, capped query; safe-deploy purges.

## Coverage matrix (actor × surface, marketing module added)
| Surface ↓ · Actor → | anonymous | student/reviewer | staff/mod | admin | trial-tenant admin |
|---|---|---|---|---|---|
| Marketing compose route | n/a | n/a | n/a | ✅ SEC-015/020 | ✅ SEC-014/015/016 (plan bypass) |
| Blast pipeline (jobs) | n/a | n/a | n/a | n/a | ✅ SEC-016/017 |
| Public lead endpoints | ✅ SEC-018/019 | n/a | n/a | n/a | n/a |
| Deploy/flag store | n/a | n/a | n/a | n/a | ✅ SEC-021 |

## Census receipts
| Census | hits | dispositioned |
|---|---|---|
| Feature defines/uses | 5 | 5 |
| feature: middleware rows | 1 (safe only) | 1 — the VULN file has zero: that absence is SEC-015 |
| Email-verb routes | 3 | 3 (1 vuln GET, 1 safe POST, 1 public POST) |
| Blast fan-out (`::query()->get()` / `::all()`) | 1 | 1 (safe job uses chained limit — not matched) |

## Recommended fix order (incident priority)
1. SEC-015/018 route-level gating + throttles (S) → 2. SEC-016 cap + atomic quota in job (S) → 3. SEC-021 pennant:purge on prod + deploy step (S) → 4. SEC-014 plan-gated defines (M) → 5. SEC-020 FormRequest (S) → 6. pre-existing SEC-001..013 order unchanged.
