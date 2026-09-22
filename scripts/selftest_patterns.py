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
    # --- config-hardening: CI workflow script injection (iac-vuln-app) ---
    ("ci-script-injection",
     r"github\.event\.pull_request\.(title|body|head\.ref)",
     "iac-vuln-app/.github/workflows/deploy.yml", "PR title: ${{"),
    # --- llm-security (llm-vuln-app) ---
    ("llm-unsafe-deserialization",
     r"(pickle|torch)\.(load|loads)",
     "llm-vuln-app/app.py", "pickle.load(f)"),
    ("llm-repl-tool",
     r"PythonREPLTool|ShellTool",
     "llm-vuln-app/app.py", "PythonREPLTool()"),
    ("llm-prompt-concat",
     r"prompt\s*=\s*f['\"]",
     "llm-vuln-app/app.py", "{user_message}"),
    ("llm-anthropic-key",
     r"sk-ant-api03-[A-Za-z0-9_-]{20,}",
     "llm-vuln-app/app.py", "sk-ant-api03-"),
    # --- vuln-db library families (java-libs-vuln, rails-libs-vuln) ---
    ("fastjson-autotype",
     r"setAutoTypeSupport|autoTypeSupport",
     "java-libs-vuln/src/main/java/com/example/web/ApiController.java", "setAutoTypeSupport(true)"),
    ("text4shell-substitutor",
     r"StringSubstitutor",
     "java-libs-vuln/src/main/java/com/example/web/ApiController.java", "StringSubstitutor.createDefault()"),
    ("shiro-default-key",
     r"kPH\+bIxk5D2deZiIxcaaaA==",
     "java-libs-vuln/src/main/java/com/example/web/ApiController.java", "kPH+bIxk5D2deZiIxcaaaA=="),
    ("rails-render-file-params",
     r"render\s+file:\s*params",
     "rails-libs-vuln/app/controllers/demos_controller.rb", "render file: params[:path]"),
    # --- config-hardening: client/API hardening (web-hardening-vuln) ---
    ("weak-csp",
     r"unsafe-(inline|eval)",
     "web-hardening-vuln/index.html", "'unsafe-inline'"),
    ("third-party-script-no-sri",
     r"<script[^>]+src=[\"']https?://",
     "web-hardening-vuln/index.html", "cdn.example-fake.com/analytics.js"),
    ("api10-upstream-innerhtml",
     r"innerHTML",
     "web-hardening-vuln/index.html", "innerHTML = data.html"),
    ("cookie-no-prefix",
     r"res\.cookie\(\s*['\"](?!__Host-|__Secure-)[^'\"]*['\"],.*secure",
     "web-hardening-vuln/app.js", "res.cookie('session'"),
    ("crlf-location-header",
     r"setHeader\(\s*['\"]Location",
     "web-hardening-vuln/app.js", "req.query.name"),
    ("api4-unbounded-find",
     r"\.find\(\s*\{\s*\}\s*\)",
     "web-hardening-vuln/app.js", "db.items.find({})"),
    # --- crypto-review (crypto-vuln-app) ---
    ("crypto-md5-password",
     r"hashlib\.md5",
     "crypto-vuln-app/app.py", "hashlib.md5(password"),
    ("crypto-ecb-mode",
     r"MODE_ECB",
     "crypto-vuln-app/app.py", "AES.MODE_ECB"),
    ("crypto-des",
     r"DES\.new\(",
     "crypto-vuln-app/app.py", "DES.new(b\"8bytekey\""),
    ("crypto-bad-random",
     r"random\.(randint|random)\(",
     "crypto-vuln-app/app.py", "random.randint"),
    ("crypto-tls-off",
     r"verify\s*=\s*False",
     "crypto-vuln-app/app.py", "verify=False"),
    ("crypto-weak-kdf",
     r"count\s*=\s*[0-9]{1,4}\b",
     "crypto-vuln-app/app.py", "count=1000"),
    # --- mobile-security: component census by type (mobile-vuln-app) ---
    ("android-exported-service",
     r"<service[^>]*android:exported=\"true\"",
     "mobile-vuln-app/AndroidManifest.xml", 'SyncService'),
    ("android-exported-activity",
     r"<activity[^>]*android:exported=\"true\"",
     "mobile-vuln-app/AndroidManifest.xml", 'AdminActivity'),
    # --- flow-security (flow-vuln-app) ---
    ("flow-client-total",
     r"req\.(body|query)\.(total|amount|price)",
     "flow-vuln-app/app.js", "req.body.total"),
    ("flow-order-id-fetch",
     r"req\.(body|query)\.order_id",
     "flow-vuln-app/app.js", "req.body.order_id"),
    ("flow-post-boundary-put",
     r"app\.put\(\s*['\"]\S*orders",
     "flow-vuln-app/app.js", "app.put('/orders/:id'"),
    ("flow-float-money",
     r"price\s*\*",
     "flow-vuln-app/app.js", "i.price * i.qty"),
    # --- dependency-vulns: beyond-CVEs pack (dep-risk-vuln-app) ---
    ("dep-vm2-usage",
     r"require\(\s*['\"]vm2['\"]\s*\)|new VM\(",
     "dep-risk-vuln-app/app.js", "new VM({"),
    ("dep-lodash-merge-usage",
     r"\.merge\(\s*\w+,\s*req\.body",
     "dep-risk-vuln-app/app.js", "_.merge(config, req.body)"),
    ("dep-request-usage",
     r"require\(\s*['\"]request['\"]\s*\)",
     "dep-risk-vuln-app/app.js", "require('request')"),
    ("dep-compromised-version",
     r"ua-parser-js['\"]\s*:\s*['\"]0\.7\.29",
     "dep-risk-vuln-app/package.json", '0.7.29'),
    ("dep-vendored-old-jquery",
     r"jQuery JavaScript Library v1\.",
     "dep-risk-vuln-app/public/vendor/jquery-1.8.3.min.js", "v1.8.3"),
    # --- proactive gap round (gaps3-vuln-app) ---
    ("tenant-unscoped-read",
     r"res\.json\(db\.reports\)",
     "gaps3-vuln-app/app.js", "res.json(db.reports)"),
    ("hook-registration-url",
     r"hooks\.push\(.*url:\s*req\.body\.url",
     "gaps3-vuln-app/app.js", "url: req.body.url"),
    ("hook-delivery-fetch",
     r"fetch\(\s*h\.url",
     "gaps3-vuln-app/app.js", "fetch(h.url"),
    ("zip-extract-overwrite",
     r"extractAllTo\(.*true\)",
     "gaps3-vuln-app/app.js", "extractAllTo("),
    ("host-substring-allowlist",
     r"host\.includes\(h\)",
     "gaps3-vuln-app/app.js", "host.includes(h)"),
    # --- C/C++ native pack (c-vuln-app) ---
    ("c-format-string",
     r"(printf|fprintf|syslog)\s*\(\s*\w+\s*[,)]|fprintf\s*\(\s*\w+,\s*[a-z_]",
     "c-vuln-app/service.c", "fprintf(stderr, user_agent)"),
    ("c-strcpy",
     r"\b(strcpy|strcat|gets|sprintf)\s*\(",
     "c-vuln-app/service.c", "strcpy(name, input)"),
    ("c-system-cmd",
     r"\bsystem\s*\(",
     "c-vuln-app/service.c", "system(cmd)"),
    # --- course-platform-security (course-vuln-app) ---
    ("catalog-unfiltered",
     r"res\.json\(db\.courses\)",
     "course-vuln-app/app.js", "res.json(db.courses)"),
    ("preview-full-content",
     r"lessons:\s*course\.content",
     "course-vuln-app/app.js", "lessons: course.content"),
    ("self-enrollment",
     r"userId:\s*req\.body\.userId",
     "course-vuln-app/app.js", "req.body.userId"),
    ("cohort-from-query",
     r"cohortId:\s*req\.query\.cohort_id",
     "course-vuln-app/app.js", "req.query.cohort_id"),
    ("admin-no-role",
     r"app\.post\(\s*['\"]\S*admin",
     "course-vuln-app/app.js", "app.post('/api/admin/courses'"),
    ("course-moderation-admin-html-sink",
     r"res\.send\(\s*`[^`]*\$\{r\.body\}",
     "course-vuln-app/app.js", "${r.body}"),
    # --- laravel-security: moderation-queue XSS census (live miss 2026-09-23) ---
    ("blade-moderation-detail-raw-render",
     r"\{!!",
     "laravel-vuln-app/resources/views/course-edit/reviews/view.blade.php", "{!! nl2br($review->body)"),
    ("blade-census-react-noise",
     r"\{!!",
     "laravel-vuln-app/resources/js/AdminDashboard.tsx", "aria-invalid={!!errors.body}"),
    ("review-validation-string-only",
     r"'body'\s*=>\s*\[\s*'required',\s*'string'",
     "laravel-vuln-app/app/Http/Requests/CourseReviewRequest.php", "'required', 'string'"),
    # --- surface round (surface-vuln-app) ---
    ("saml-nonstrict",
     r"['\"]strict['\"]\s*:\s*False",
     "surface-vuln-app/saml_route.py", '"strict": False'),
    ("saml-unsigned",
     r"want(Response|Assertions)Signed['\"]\s*:\s*False",
     "surface-vuln-app/saml_route.py", "wantResponseSigned"),
    ("k8s-escalate-verbs",
     r"verbs:\s*\[.*['\"](escalate|bind|impersonate)['\"]",
     "surface-vuln-app/clusterrole.yaml", '"escalate", "bind"'),
    ("serverless-wildcard-iam",
     r"Action:\s*['\"]\*['\"]",
     "surface-vuln-app/serverless.yml", 'Action: "*"'),
    ("serverless-authorizer-none",
     r"authorizer:\s*none",
     "surface-vuln-app/serverless.yml", "authorizer: none"),
    ("devart-vscode-token",
     r"GITHUB_TOKEN['\"]?\s*[:=]",
     "surface-vuln-app/.vscode/launch.json", 'GITHUB_TOKEN'),
    ("devart-postman-bearer",
     r"Bearer eyJ[A-Za-z0-9_.-]+",
     "surface-vuln-app/shop-api.postman_collection.json", 'Bearer eyJ'),
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
    ("llm-deserialization-safe",
     r"(pickle|torch)\.(load|loads)\(",
     "llm-vuln-app/safe_app.py"),
    ("llm-key-safe",
     r"sk-ant-api03-[A-Za-z0-9_-]{20,}",
     "llm-vuln-app/safe_app.py"),
    ("fastjson-autotype-safe",
     r"setAutoTypeSupport\(true\)|autoTypeSupport",
     "java-libs-vuln/src/main/java/com/example/web/SafeController.java"),
    ("shiro-default-key-safe",
     r"kPH\+bIxk5D2deZiIxcaaaA==|setCipherKey",
     "java-libs-vuln/src/main/java/com/example/web/SafeController.java"),
    ("weak-csp-safe",
     r"unsafe-(inline|eval)",
     "web-hardening-vuln/safe-index.html"),
    ("api10-innerhtml-safe",
     r"innerHTML",
     "web-hardening-vuln/safe-index.html"),
    ("crypto-md5-safe",
     r"hashlib\.md5",
     "crypto-vuln-app/safe_app.py"),
    ("crypto-ecb-tls-off-safe",
     r"MODE_ECB|verify\s*=\s*False",
     "crypto-vuln-app/safe_app.py"),
    ("flow-client-total-safe",
     r"req\.(body|query)\.(total|amount|price)",
     "flow-vuln-app/safe-flow.js"),
    ("flow-unguarded-assign-safe",
     r"Object\.assign\(order,\s*req\.body\)",
     "flow-vuln-app/safe-flow.js"),
    ("dep-vm2-request-safe",
     r"require\(\s*['\"](vm2|request)['\"]\s*\)",
     "dep-risk-vuln-app/safe-app.js"),
    ("dep-merge-reqbody-safe",
     r"\.merge\(\s*\w+,\s*req\.body",
     "dep-risk-vuln-app/safe-app.js"),
    ("dep-vendored-old-jquery-safe",
     r"jQuery JavaScript Library v1\.",
     "dep-risk-vuln-app/public/vendor/jquery-3.7.1.min.js"),
    ("tenant-unscoped-safe",
     r"res\.json\(db\.reports\)",
     "gaps3-vuln-app/safe-gaps3.js"),
    ("zip-extract-overwrite-safe",
     r"extractAllTo\([^)]*true\)",
     "gaps3-vuln-app/safe-gaps3.js"),
    ("host-substring-safe",
     r"host\.includes\(h\)",
     "gaps3-vuln-app/safe-gaps3.js"),
    ("c-format-string-safe",
     r"fprintf\s*\(\s*\w+,\s*[a-z_]",
     "c-vuln-app/safe_service.c"),
    ("c-strcpy-safe",
     r"\b(strcpy|strcat|gets)\s*\(",
     "c-vuln-app/safe_service.c"),
    ("catalog-unfiltered-safe",
     r"res\.json\(db\.courses\)",
     "course-vuln-app/safe-platform.js"),
    ("self-enrollment-safe",
     r"userId:\s*req\.body\.userId",
     "course-vuln-app/safe-platform.js"),
    ("course-moderation-unescaped-safe",
     r"res\.send\(\s*`[^`]*\$\{r\.body\}",
     "course-vuln-app/safe-platform.js"),
    ("moderation-list-raw-echo-safe",
     r"\{!!",
     "laravel-vuln-app/resources/views/course-edit/reviews/index.blade.php"),
    ("moderation-detail-raw-body-safe",
     r"nl2br\(\s*\$review->body",
     "laravel-vuln-app/resources/views/course-edit/reviews/safe-detail-view.blade.php"),
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
