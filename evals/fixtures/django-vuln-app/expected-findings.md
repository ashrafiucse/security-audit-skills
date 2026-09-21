# django-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Hardcoded SECRET_KEY + DB password in settings | settings.py:2,14 | Critical |
| 2 | `DEBUG = True` | settings.py:4 | High |
| 3 | `ALLOWED_HOSTS = ['*']` (host-header poisoning of reset links) | settings.py:5 | Medium |
| 4 | Insecure CSRF/session cookies | settings.py:7-8 | Medium |
| 5 | SQL injection via `raw()` f-string | views.py:9-11 | Critical |
| 6 | XSS via `mark_safe(user_input)` | views.py:17 | High |
| 7 | IDOR — invoice fetched by pk without ownership check | views.py:22 | High |
| 8 | Mass assignment — ModelForm `fields = '__all__'` on profile with role flags | forms.py:10 | High |
| 9 | XSS via `\|safe` filter in template | templates/greet.html:2 | High |
| 10 | Django 2.2.0 + DRF 3.9.1 (live OSV: many CVEs, EOL) | requirements.txt | High (network-dependent) |

## Must NOT trigger

- `{{ count }}` (auto-escaped)
- ORM usage itself (parameterized — the safe counterpart to finding 5)
