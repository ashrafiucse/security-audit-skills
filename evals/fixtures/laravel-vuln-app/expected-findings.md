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
| — | laravel/framework 8.83.1 (live OSV advisories — informational, network-dependent) | composer.json:6 | High |

## Must NOT trigger

- `{{ $name }}` on greeting.blade.php:5 (escaped — the safe counterpart)
- `storage_path()` call itself (only the user-controlled concatenation matters)
- `response()->json($user)` (JSON response, not an XSS sink)
- `{{ $review->body }}` on resources/views/course-edit/reviews/index.blade.php:7 — the moderation LIST view escapes; only the detail view is raw
- `{!! nl2br(e($review->body)) !!}` on resources/views/course-edit/reviews/safe-detail-view.blade.php:4 — legitimate raw-echo grep hit, but escaped inside (`e()` first); disposition: verified-safe
- `aria-invalid={!!errors.body}` on resources/js/AdminDashboard.tsx:5 — React/JSX double-negation, NOT Blade; this is the noise an un-globbed scan drowns in (why Step 4 globs to `*.blade.php`)
