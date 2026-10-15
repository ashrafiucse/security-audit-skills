# wp-vuln-app — Expected findings

Ground truth for `evals/fixtures/wp-vuln-app` (WordPress-shaped micro-fixture:
do_shortcode-on-input class, SSTI's PHP flavor — triage round for
CVE-2026-92966 / LatePoint).

| # | Class | Finding | Where | Severity |
|---|---|---|---|---|
| 1 | Template injection (SSTI, WP shortcodes) | `do_shortcode($_POST['content'])` inside a `wp_ajax_nopriv_*` handler — unauthenticated arbitrary shortcode execution: every shortcode the site's plugins register becomes callable (LatePoint CVE-2026-92966 class) | vuln.php:6-9 | Critical |
| 2 | OS command injection, obfuscated-case PHP sink | `SyStem('ping -c 1 ' . $_GET['host'])` in a nopriv handler — PHP function calls are case-insensitive, so the mixed-case spelling evades case-sensitive sink greps while remaining a full shell-exec of request data (semgrep php exec-use went case-insensitive 2026-10; this plant defeats the pre-fix grep and is caught by the `-i` census) | vuln.php:12-20 | Critical |

## Must NOT trigger (near-misses — `safe_wp.php`)

- `safe_wp.php:5-9` — `do_shortcode('[latepoint_booking calendar="main"]')`: the sink fires on a server-side CONSTANT — nothing client-controlled reaches the template-execution path. The grep hit is expected; the disposition is "constant template, not request data" (the SSTI rule's data-context vs template-string distinction).
- `vuln.php:3` — the fixture header comment mentions `do_shortcode()` (documentation noise, not a sink call).
- `vuln.php:13` — the SEC-2 comment mentions `system()` lowercase — documentation noise for the case-insensitivity lesson; the SINK is the mixed-case `SyStem(` call on line 17.
- `safe_wp.php:14-20` — the diag handler validates via `escapeshellarg` and runs a LITERAL command through an argument array (`exec('ping', array(...))`): the case-insensitive census grep fires on it BY DESIGN (expected hit); the disposition is "literal command + argument array + escaped input" — the vuln subshape (string-concat of `$_GET` into the call) does not occur anywhere in the file.

## Out of ground truth

- No plugin version manifests here — LatePoint-the-plugin detection (folder +
  `Version:` header gate `<= 5.7.0`) lives in the vuln-db entry
  (`skills/cve-research/vuln-db/entries/2026-10-01-cve-2026-92966.md`), not in
  this code-pattern fixture.
- Live OSV/KEV results are informational, never deterministic ground truth.
