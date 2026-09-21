# rails-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | SQL injection via interpolated `where` | users_controller.rb:8 | Critical |
| 2 | XSS via `raw` on user bio | show.html.erb:2 | High |
| 3 | CSRF skipped controller-wide | users_controller.rb:3 | High |
| 4 | No authenticate/authorize before_action | users_controller.rb:5 | High |
| 5 | Mass assignment via `permit!` (admin column reachable) | users_controller.rb:24,13 | Critical |
| 6 | Path traversal via `send_file(params[:path])` | users_controller.rb:21 | High |
| 7 | Arbitrary method dispatch `public_send(params[:method])` | users_controller.rb:25 | High |
| 8 | `force_ssl = false` in production | production.rb:2 | Medium |
| 9 | Committed `secret_key_base` | config/secrets.yml:2 | Critical |
| 10 | rails 5.2.3 / devise 4.7.1 / pg 1.1.4 (live OSV) | Gemfile | High (network-dependent) |

## Must NOT trigger

- `<%= @user.name %>` (escaped counterpart)
- `User.find(params[:id])` alone in `show` (authz context missing → note, but not Critical by itself)
