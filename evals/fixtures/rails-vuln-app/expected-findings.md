# rails-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | SQL injection via interpolated `where` | users_controller.rb:9 | Critical |
| 2 | XSS via `raw` on user bio | show.html.erb:2 | High |
| 3 | CSRF skipped controller-wide | users_controller.rb:4 | High |
| 4 | No authenticate/authorize before_action | users_controller.rb:6 | High |
| 5 | Mass assignment via `permit!` (admin column reachable) | users_controller.rb:36 (used at 13-16) | Critical |
| 6 | Path traversal via `send_file(params[:path])` | users_controller.rb:25 | High |
| 7 | Arbitrary method dispatch `public_send(params[:method])` | users_controller.rb:30 | High |
| 8 | `force_ssl = false` in production | production.rb:2 | Medium |
| 9 | Committed `secret_key_base` | config/secrets.yml:2 | Critical |
| 10 | Over-returning — `render json: user` leaks every column incl. admin/password digest | users_controller.rb:16 | Medium |
| 11 | No lockfile — `Gemfile.lock` absent, non-reproducible installs (file-level anchor) | Gemfile:- | High |
| 12 | Moderation-view XSS — `raw @review.body` in the staff moderation partial (privilege direction: unprivileged→privileged = Critical) | app/views/reviews/_moderation.html.erb:4 | Critical |
| — | rails 5.2.3 / devise 4.7.1 / pg 1.1.4 (live OSV — informational, network-dependent) | Gemfile | High |

## Must NOT trigger

- `<%= @user.name %>` (escaped counterpart)
- `<%= @review.body %>` in app/views/reviews/_safe_moderation.html.erb:2 (escaped moderation counterpart)
- `User.find(params[:id])` alone in `show` (authz context missing → note, but not Critical by itself)
