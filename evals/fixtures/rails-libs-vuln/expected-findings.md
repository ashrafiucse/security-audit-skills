# rails-libs-vuln — Expected findings

Ground truth for `evals/fixtures/rails-libs-vuln` (CVE-2019-5418 pattern).

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | `render file: params[:path]` — request-derived template path (arbitrary file read; CVE-2019-5418 pattern on any rails version) | demos_controller.rb:4-6 | High |

## Must NOT trigger (near-miss)

- `render file: Rails.root.join("app/views/demos/about")` — first-party literal
