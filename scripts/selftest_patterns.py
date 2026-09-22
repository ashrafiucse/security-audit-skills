#!/usr/bin/env python3
"""selftest_patterns.py - verify detection greps still match their fixtures.

Each rule: (regex, fixture path, line substring that MUST be matched by >=1 hit).
Guards against pattern rot: if a references/SKILL.md grep is edited and stops
catching its planted finding, CI fails here before recall silently degrades.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "evals" / "fixtures"

RULES = [
    # --- injection-flaws: new classes (node-vuln-app-2) ---
    ("nosql-operator-injection",
     r"(find|findOne|findOneAndUpdate|updateOne|deleteOne|aggregate)\(\s*\{\s*\.\.\.(req|ctx|event)\.|\{\s*\.\.\.(body|query|params)|find(One)?\(\s*\{[^}]*req\.(body|query)",
     "node-vuln-app-2/app.js", "findOne({ email: req.body.email"),
    ("prototype-pollution",
     r"(deepMerge|defaultsDeep|merge\(|extend\(|\.set\()\(.*req\.(body|query|params)|Object\.assign\(\s*\{\}\s*,\s*req\.(body|query)",
     "node-vuln-app-2/app.js", "deepMerge(featureFlags, req.body)"),
    ("open-redirect-js",
     r"res\.redirect\(",
     "node-vuln-app-2/app.js", "res.redirect(req.query.next"),
    ("header-trust-authz",
     r"req\.headers\[\s*['\"]x-",
     "node-vuln-app-2/app.js", "req.headers['x-user-id']"),
    ("websocket-authz",
     r"socket\.on\(",
     "node-vuln-app-2/app.js", "socket.on('orders:subscribe'"),
    ("upload-filename",
     r"originalname",
     "node-vuln-app-2/app.js", "cb(null, file.originalname)"),
    # --- injection-flaws: new classes (python-vuln-app-2) ---
    ("xxe-lxml",
     r"etree\.(parse|fromstring)",
     "python-vuln-app-2/app.py", "etree.fromstring(request.get_data())"),
    ("xxe-stdlib-import",
     r"xml\.etree",
     "python-vuln-app-2/app.py", "import xml.etree.ElementTree as ET"),
    ("open-redirect-py",
     r"redirect\(request",
     "python-vuln-app-2/app.py", "redirect(request.args.get"),
    # --- auth-review: existing core classes stay covered (rails fixture) ---
    ("idor-sink",
     r"req\.params\.id|findById\(",
     "node-vuln-app/app.js", "req.params.id"),
    # --- auth-review: route census (node-vuln-app-3) ---
    ("route-census",
     r"app\.(get|post|put|patch|delete|all)\(",
     "node-vuln-app-3/app.js", "app.get('/admin/users'"),
    # --- injection-flaws: second-order + builder + worker (node-vuln-app-3) ---
    ("stored-xss-read-path",
     r"<%-",
     "node-vuln-app-3/views/profile.ejs", "user.bio"),
    ("query-builder-raw",
     r"\.raw\(",
     "node-vuln-app-3/app.js", "knex.raw('SELECT * FROM products ORDER BY '"),
    ("queue-worker-exec",
     r"exec\(",
     "node-vuln-app-3/app.js", "exec(`convert"),
    # --- container-iac-security + config-hardening CI (iac-vuln-app) ---
    ("k8s-privileged",
     r"privileged:\s*true",
     "iac-vuln-app/deployment.yaml", "privileged: true"),
    ("k8s-run-as-root",
     r"runAsUser:\s*0",
     "iac-vuln-app/deployment.yaml", "runAsUser: 0"),
    ("tf-open-ingress",
     r"0\.0\.0\.0/0",
     "iac-vuln-app/main.tf", 'cidr_blocks = ["0.0.0.0/0"]'),
    ("tf-unencrypted-db",
     r"storage_encrypted\s*=\s*false",
     "iac-vuln-app/main.tf", "storage_encrypted = false"),
    ("ci-pull-request-target",
     r"pull_request_target",
     "iac-vuln-app/.github/workflows/deploy.yml", "pull_request_target:"),
    ("ci-untrusted-checkout",
     r"github\.event\.pull_request\.head\.sha",
     "iac-vuln-app/.github/workflows/deploy.yml", "ref: ${{"),
    ("ci-tag-pinned-action",
     r"uses:\s*\S+@v\d",
     "iac-vuln-app/.github/workflows/deploy.yml", "actions/checkout@v4"),
    # --- auth-review: mass assignment (node-vuln-app-3) ---
    ("mass-assignment",
     r"\.update\(\s*req\.body",
     "node-vuln-app-3/app.js", ".update(req.body)"),
    # --- container-iac: IMDSv1 allowed (iac-vuln-app) ---
    ("imds-v1-allowed",
     r"http_tokens\s*=\s*\"optional\"",
     "iac-vuln-app/main.tf", 'http_tokens   = "optional"'),
    # --- config-hardening: postMessage (spa-vuln-app) ---
    ("postmessage-listener",
     r"addEventListener\(\s*['\"]message",
     "spa-vuln-app/index.html", "addEventListener('message'"),
]

# Raw-vulnerable-form patterns that must have ZERO hits in the safe counter-example files.
MUST_NOT_MATCH = [
    ("nosql-raw-body-query-safe",
     r"find(One)?\(\s*\{[^}]*req\.(body|query)",
     "node-vuln-app-2/safe-counterexamples.js"),
    ("merge-user-keys-safe",
     r"(deepMerge|merge\(|extend\(|\.set\()\(.*req\.(body|query|params)",
     "node-vuln-app-2/safe-counterexamples.js"),
    ("redirect-no-allowlist-safe",
     r"res\.redirect\(\s*req\.",
     "node-vuln-app-2/safe-counterexamples.js"),
    ("xxe-unsafe-parser-safe",
     r"(etree|ET)\.(parse|fromstring)\(\s*request",
     "python-vuln-app-2/safe_counterexamples.py"),
    ("redirect-raw-request-safe",
     r"redirect\(\s*request",
     "python-vuln-app-2/safe_counterexamples.py"),
    ("ejs-unescaped-read-safe",
     r"<%-",
     "node-vuln-app-3/safe-counterexamples.js"),
    ("unguarded-admin-route-safe",
     r"app\.get\(\s*['\"]\S*admin\S*['\"]\s*,\s*async",
     "node-vuln-app-3/safe-counterexamples.js"),
    ("k8s-privileged-safe",
     r"privileged:\s*true|runAsUser:\s*0",
     "iac-vuln-app/hardened-deployment.yaml"),
    ("mass-assignment-safe",
     r"\.update\(\s*req\.body",
     "node-vuln-app-3/safe-counterexamples.js"),
    ("postmessage-innerhtml-safe",
     r"innerHTML",
     "spa-vuln-app/safe-index.html"),
]

# Multi-line rules: matched against the WHOLE FILE (python re, [\s\S] spans lines) —
# mirrors the bounded `rg -U` scans in injection-flaws.
CONTENT_RULES = [
    ("multiline-query-build",
     r"raw\(\s*`[\s\S]{0,300}(WHERE|ORDER BY)[\s\S]{0,300}\$\{",
     "node-vuln-app-3/app.js", "WHERE status = '${status}'"),
]


def load(path):
    return path.read_text(encoding="utf-8").splitlines()


def run():
    failures = []
    for name, pattern, fixture, expected_sub in RULES:
        path = FIXTURES / fixture
        lines = load(path)
        rx = re.compile(pattern)
        hits = [(i, ln) for i, ln in enumerate(lines, 1) if rx.search(ln)]
        if not any(expected_sub in ln for _, ln in hits):
            failures.append(
                f"{name}: pattern no longer matches planted line in {fixture} "
                f"(expected substring {expected_sub!r}; {len(hits)} raw hits)")
    for name, pattern, fixture in MUST_NOT_MATCH:
        path = FIXTURES / fixture
        rx = re.compile(pattern)
        hits = [ln for ln in load(path) if rx.search(ln)]
        if hits:
            failures.append(
                f"{name}: vulnerable form matches {len(hits)} line(s) in {fixture}; "
                f"first: {hits[0].strip()[:100]}")
    for name, pattern, fixture, expected_sub in CONTENT_RULES:
        text = (FIXTURES / fixture).read_text(encoding="utf-8")
        rx = re.compile(pattern)
        if not any(expected_sub in m.group(0) for m in rx.finditer(text)):
            failures.append(
                f"{name}: multi-line pattern no longer matches {fixture} "
                f"(expected substring {expected_sub!r})")
    if failures:
        print("SELFTEST FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"selftest_patterns: {len(RULES)} match rules + "
          f"{len(MUST_NOT_MATCH)} no-match + {len(CONTENT_RULES)} multi-line OK")
    return 0


if __name__ == "__main__":
    sys.exit(run())
