# wp-vuln-app — Expected findings

Ground truth for `evals/fixtures/wp-vuln-app` (WordPress-shaped micro-fixture:
do_shortcode-on-input class, SSTI's PHP flavor — triage round for
CVE-2026-92966 / LatePoint).

| # | Class | Finding | Where | Severity |
|---|---|---|---|---|
| 1 | Template injection (SSTI, WP shortcodes) | `do_shortcode($_POST['content'])` inside a `wp_ajax_nopriv_*` handler — unauthenticated arbitrary shortcode execution: every shortcode the site's plugins register becomes callable (LatePoint CVE-2026-92966 class) | vuln.php:6-9 | Critical |

## Must NOT trigger (near-misses — `safe_wp.php`)

- `safe_wp.php:5-9` — `do_shortcode('[latepoint_booking calendar="main"]')`: the sink fires on a server-side CONSTANT — nothing client-controlled reaches the template-execution path. The grep hit is expected; the disposition is "constant template, not request data" (the SSTI rule's data-context vs template-string distinction).
- `vuln.php:3` — the fixture header comment mentions `do_shortcode()` (documentation noise, not a sink call).

## Out of ground truth

- No plugin version manifests here — LatePoint-the-plugin detection (folder +
  `Version:` header gate `<= 5.7.0`) lives in the vuln-db entry
  (`skills/cve-research/vuln-db/entries/2026-10-01-cve-2026-92966.md`), not in
  this code-pattern fixture.
- Live OSV/KEV results are informational, never deterministic ground truth.
