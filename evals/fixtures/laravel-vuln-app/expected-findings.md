# laravel-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Committed `.env` with `APP_KEY` (cookie-forgery → deserialization RCE chain) | .env:3 | Critical |
| 1b | `DB_PASSWORD` committed in same `.env` | .env:9 | High |
| 2 | `APP_DEBUG=true` while `APP_ENV=production` | .env:4 | High |
| 3 | Mass assignment: `$guarded = []` + `User::create($request->all())` (is_admin self-promotion) | app/Models/User.php:10, UserController.php:15 | Critical |
| 4 | SQL injection via `DB::raw` concatenation | UserController.php:21-24 | Critical |
| 5 | Path traversal in `response()->download()` | UserController.php:30 | High |
| 6 | Admin/state-changing routes without auth middleware | routes/web.php:10-13 | High |
| 7 | CSRF disabled globally (`$except = ['*']`) | VerifyCsrfToken.php:12-14 | High |
| 8 | Blade raw output `{!! $name !!}` | greeting.blade.php:4 | High |
| 9 | debugbar in production `require` (dev tool) | composer.json:7 | Medium |
| 10 | No composer.lock — non-reproducible installs, transitive-swap risk (file-level anchor) | composer.json:- | High |
| 11 | Moderation-queue XSS chain: review body accepted as raw HTML (`required|string` only), stored unpurified, raw-rendered in the STAFF detail view `{!! nl2br($review->body) !!}` — student authors, admin views → admin-origin XSS → staff account takeover. Pending status guarantees a privileged viewer opens it (privilege-direction: unprivileged→privileged = Critical) | CourseReviewRequest.php:14, CreateCourseReviewAction.php:17, resources/views/course-edit/reviews/view.blade.php:6 | Critical |
| 12 | Support/email channel XSS: student support message rendered raw in the staff HTML mail view (`{!! $ticket->body !!}`) — fires where mail HTML renders (webmail preview / support desk); same privilege direction (student writes, staff reads) | resources/views/mail/support-ticket.blade.php:6 | Critical |
| 13 | Grading channel XSS: quiz/assignment answer rendered raw (`{!! nl2br($answer->text) !!}`) in the grader's view — grading workflows force staff to open every pending answer | resources/views/course-edit/quiz/grade.blade.php:5 | Critical |
| 14 | Feature-flag default-true for a dangerous capability: `Feature::define('import-leads', true)` — global enable, no per-plan constraint (incident class 2026-09-23) | modules/marketing/src/Providers/MarketingServiceProvider.php:17 | High |
| 15 | Flag gated in UI/job only: compose route carries `auth` but NO `feature:` middleware and NO throttle — route is the enforcement point (F9 enabler) | modules/marketing/routes/web.php:8-9 | Critical |
| 16 | Blast amplification (F9): job loads `Lead::query()->get()` unbounded, dispatches one mail job per lead, no recipient cap, no quota | modules/marketing/src/Jobs/ProcessEmailBlast.php:10-19 | Critical |
| 17 | `send-email` flag checked ONLY inside the queued job — defense-in-depth deployed as the only gate | modules/marketing/src/Jobs/SendEmailToEmailBlastRecipient.php:13 | High |
| 18 | Public GET with side effect: `send-verification-link` — no auth, no throttle; ID enumeration = mail bomb (works with zero flags) | modules/marketing/routes/web.php:12 | Critical |
| 19 | Public subscribe POST — no FormRequest, no throttle, no captcha (email-triggering public endpoint) | modules/marketing/routes/api.php:7 | High |
| 20 | `composeEmail` uses `$request->all()` into the DTO — attacker-controlled subject/body = phishing from the platform domain | modules/marketing/src/Http/Controllers/LeadController.php:13 | High |
| 21 | Pennant database store + no `pennant:purge` in deploy scripts — stored per-scope values survive flag-default reverts (absence finding) | config/pennant.php:6, deploy/deploy.sh:- | Medium |
| — | laravel/framework 8.83.1 (live OSV advisories — informational, network-dependent) | composer.json:6 | High |

## Must NOT trigger

- `{{ $name }}` on greeting.blade.php:5 (escaped — the safe counterpart)
- `storage_path()` call itself (only the user-controlled concatenation matters)
- `response()->json($user)` (JSON response, not an XSS sink)
- `{{ $review->body }}` on resources/views/course-edit/reviews/index.blade.php:7 — the moderation LIST view escapes; only the detail view is raw
- `{!! nl2br(e($review->body)) !!}` on resources/views/course-edit/reviews/safe-detail-view.blade.php:4 — legitimate raw-echo grep hit, but escaped inside (`e()` first); disposition: verified-safe
- `aria-invalid={!!errors.body}` on resources/js/AdminDashboard.tsx:5 — React/JSX double-negation, NOT Blade; this is the noise an un-globbed scan drowns in (why Step 4 globs to `*.blade.php`)
- `{{ $ticket->body }}` on resources/views/mail/safe-support-ticket.blade.php:6 — escaped support-mail render (safe counterpart of row 12)
- `{!! nl2br(e($answer->text)) !!}` on resources/views/course-edit/quiz/safe-grade.blade.php:4 — escape-then-format grading render (safe counterpart of row 13)
- Note: the Step 4 census glob (`*.blade.php`) automatically includes mail views — channels are covered by the same census, not a separate scan
- `SafeMarketingServiceProvider.php:18-19` — plan-closure defines (`fn (Tenant $t) => $t->onPaidPlan()`), no literal-true defaults
- `modules/marketing/routes/safe-web.php:7-8` — compose route carries `feature:send-email` + `throttle:blast-compose` (route = enforcement point); `:11-12` verification link is POST + signed + throttled
- `SafeLeadController.php:10,13` — `ComposeEmailRequest` FormRequest + `$request->validated()` (no `->all()`)
- `SafeProcessEmailBlast.php:10,13-19` — atomic `BlastQuota::consumeForTenant` + verified-only + `->limit(500)`; the `::query()->get()` adjacency pattern does not hit the chained form
- `deploy/safe-deploy.sh:8` — `pennant:purge` present (the deploy.sh absence is the row-21 finding)
