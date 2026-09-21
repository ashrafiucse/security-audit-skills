# laravel-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Committed `.env` with `APP_KEY` (cookie-forgery → deserialization RCE chain) + `DB_PASSWORD` | .env:3,9 | Critical |
| 2 | `APP_DEBUG=true` while `APP_ENV=production` | .env:4 | High |
| 3 | Mass assignment: `$guarded = []` + `User::create($request->all())` (is_admin self-promotion) | app/Models/User.php:10, UserController.php:15 | Critical |
| 4 | SQL injection via `DB::raw` concatenation | UserController.php:21-24 | Critical |
| 5 | Path traversal in `response()->download()` | UserController.php:30 | High |
| 6 | Admin/state-changing routes without auth middleware | routes/web.php:10-13 | High |
| 7 | CSRF disabled globally (`$except = ['*']`) | VerifyCsrfToken.php:12-14 | High |
| 8 | Blade raw output `{!! $name !!}` | greeting.blade.php:4 | High |
| 9 | debugbar in production `require` (dev tool) | composer.json:7 | Medium |
| 10 | laravel/framework 8.83.1 (live OSV advisories) | composer.json:6 | High (network-dependent) |

## Must NOT trigger

- `{{ $name }}` on greeting.blade.php:5 (escaped — the safe counterpart)
- `storage_path()` call itself (only the user-controlled concatenation matters)
- `response()->json($user)` (JSON response, not an XSS sink)
