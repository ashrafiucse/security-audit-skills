# Security Audit — rails-libs-vuln (fixture)
Date: 2026-09-22 | Scope: working tree (evals/fixtures/rails-libs-vuln) | Auditor: security-skills (session audit)
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: not run (no network, per audit constraints)

## Stack
Minimal Rails fixture: single controller (`app/controllers/demos_controller.rb`, 12 lines) with
two actions (`show`, `about`). No Gemfile/Gemfile.lock (Rails/actionview version UNKNOWN —
affects CVE range checks), no ApplicationController, no routes.rb, no views, no models, no
config. Entry points: `DemosController#show`, `DemosController#about` (assumed routed).
No auth mechanism, no database, no external services visible.

## Summary
| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 0 |
| Low | 0 |

Completed chains: none (single-finding surface — see "What would make this worse").

## Findings

### SEC-001: Arbitrary file read via request-derived `render file:` path — HIGH
- **Where:** `app/controllers/demos_controller.rb:6`
- **CWE:** CWE-22 (Path Traversal) / CWE-74; CVE-2019-5418 pattern (vuln-db entry `2019-03-13-cve-2019-5418`)
- **Evidence:**
  ```ruby
  def show
    render file: params[:path]
  end
  ```
- **Impact:** The user-supplied `params[:path]` is handed to Action View as the template
  path — an unauthenticated caller reads arbitrary files from the server (source code,
  `config/secrets.yml`, `config/master.key`, environment files). On vulnerable actionview
  ranges (5.2.x <5.2.2.1, 5.1.x <5.1.6.2, 5.0.x <5.0.7.2, 4.2.x <4.2.11.1, per the
  CVE-2019-5418 entry) the Accept-header trick makes even relative paths readable; per the
  rails-security skill, even on PATCHED rails this exact pattern remains a design bug worth
  High — the framework fix narrowed the read primitive, it did not make request data a
  valid template path. Rails version is unknown here (no Gemfile), so the CVE range itself
  could not be verified — treat the code pattern as the finding. Likelihood: reachable from
  unauthenticated input (no auth surface in scope). Effort: S.
- **Fix:** Never derive a render path from the request. If dynamic templates are truly
  needed, use an allowlist map:
  ```ruby
  TEMPLATES = { "about" => "demos/about", "help" => "demos/help" }.freeze
  def show
    render template: TEMPLATES[params[:page]] or render file: Rails.root.join("app/views/demos/#{TEMPLATES.fetch(params[:page])}")
  end
  ```
  Additionally: pin rails/actionview in a Gemfile.lock and verify the version against the
  CVE-2019-5418 fixed lines (≥5.2.2.1 / 5.1.6.2 / 5.0.7.2 / 4.2.11.1).
- **References:** CVE-2019-5418, rails-security SKILL Step 5, CWE-22

## What looks good
- `DemosController#about` (`demos_controller.rb:10-11`): `render file: Rails.root.join("app/views/demos/about")`
  — first-party literal path, the correct counterpart to SEC-001; explicitly the safe form
  per the rails-security skill.
- No SQL/string-interpolation sinks, no `raw`/`html_safe` usage, no deserialization calls,
  no command-execution sinks, no secrets detected in the scanned tree (secrets scan clean).

## OWASP completeness gate (A01–A10)
A01/A05/A07: **not assessed** — no ApplicationController/routes/config exist in scope, so
CSRF posture, authn/authz before_actions, and framework config cannot be evaluated (fixture
minimalism, not evidence of safety). A02/A04/A08/A09/A10: no corresponding surface (no
crypto, no flows, no CI/supply-chain files, no logging, no outbound fetch). A03: covered
(SEC-001). A06: no manifest present — dependency version is UNKNOWN; noted inside SEC-001.

## What would make this worse (prioritized hardening, not findings)
- A committed `secret_key_base`/`master.key` would chain SEC-001 (file read) → session
  forgery → account takeover; verify none exists in the real app this pattern came from.
- No visible rate limiting on the read primitive — brute-path discovery stays cheap.

## Recommended fix order
1. SEC-001 — replace `params[:path]` with an allowlisted template map (S effort) and pin
   actionview in a lockfile to confirm the CVE-2019-5418 fixed line.
