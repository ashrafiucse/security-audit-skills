# Security Audit — spa-vuln-app
Date: 2026-09-22 | Scope: working tree (no git history) | Auditor: security-skills v1.2.0-36-g433fb22-dirty (git describe unavailable in fixture dir; v1.2.0 line)
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: not-run (no network per audit constraints)

## Stack
Single-page static HTML/JS embed page (`index.html`) plus a hardened
counterpart demo (`safe-index.html`). No build system, no dependency
manifests, no server code, no infra files. Trust surface: `postMessage`
communication with parent/embedding windows; session token held in
`sessionStorage`. Size class: trivial (2 first-party files).

## Summary
| Severity | Count |
|---|---|
| Critical | 1 |
| High | 1 |
| Medium | 2 |
| **Total** | **4** |

Completed chains (Phase 2.5):
- **SEC-001 + SEC-003 → XSS → session theft → account takeover**: any window that can message this page injects HTML; the page's sessionStorage holds the live session token, readable by the injected script.

## Findings

### SEC-001: Cross-origin XSS via postMessage — no origin check, `innerHTML` sink — CRITICAL
- **Where:** `index.html:8-10`
- **CWE:** CWE-346 (Origin Validation Error) + CWE-79 (XSS)
- **Evidence:**
  ```js
  window.addEventListener('message', (e) => {
    document.getElementById('out').innerHTML = e.data;
  });
  ```
  The handler never compares `e.origin` against an allowlist, and the
  message payload is written directly into `innerHTML` (HTML parsing sink).
- **Impact:** Any window holding a reference to this page — an embedding
  iframe's parent (or any page that opened it) — delivers `e.data` rendered
  as live HTML/`<script>` context → arbitrary JavaScript in this page's
  origin. Because the page also holds the session token in sessionStorage
  (SEC-003), the practical outcome is account takeover via one `postMessage`
  call. Unauthenticated, no user interaction beyond page load.
- **Fix:** Validate the source and escape the sink (both are required):
  ```js
  const ALLOWED_ORIGIN = 'https://app.example.com';
  window.addEventListener('message', (e) => {
    if (e.origin !== ALLOWED_ORIGIN) return;
    document.getElementById('out').textContent = String(e.data); // safe sink
  });
  ```
  If rich HTML from the trusted parent is genuinely needed, sanitize with
  DOMPurify before insertion — never raw `innerHTML`.
- **References:** OWASP A03; MDN postMessage security notes. Safe counterpart
  exists in this repo: `safe-index.html:8-11`.

### SEC-002: Session token broadcast to ANY origin (`postMessage(..., '*')`) — HIGH
- **Where:** `index.html:13`
- **CWE:** CWE-200 (Exposure of Sensitive Information) / CWE-359
- **Evidence:**
  ```js
  window.parent.postMessage({ token: sessionStorage.getItem('session') }, '*');
  ```
  The live session credential is sent to `'*'` — every parent/embedding
  window receives it, regardless of who embedded the page (skill baseline
  rates wildcard-with-sensitive-payload Medium; upgraded to High because the
  payload is the session credential itself — full account access).
- **Impact:** An attacker who embeds this page in their own page (or gets a
  victim's page embedded adjacent) receives the victim's session token
  directly — no XSS required. Token → replay → account takeover.
- **Fix:** Send to an explicit origin, and don't ship the token at all:
  ```js
  window.parent.postMessage({ theme: 'dark' }, 'https://app.example.com');
  ```
  Sensitive values should never cross frames via postMessage; the parent
  already owns its session.
- **References:** OWASP A02; `config-hardening` §7 wildcard-targetOrigin rule.

### SEC-003: Session token stored in JS-readable sessionStorage — MEDIUM (chain-critical)
- **Where:** `index.html:13` (read site)
- **CWE:** CWE-525 (Sensitive Info in Client-Readable Storage) / CWE-922
- **Evidence:**
  ```js
  sessionStorage.getItem('session')
  ```
  The session credential is accessible to any script running in the page's
  origin.
- **Impact:** Standalone: any script-injection bug in this page (SEC-001, or
  any future dependency XSS — note there are no integrity-protected
  dependencies here, just inline code) converts directly into credential
  theft. Tagged **chain-critical**: it is the completing component of the
  SEC-001 → session-theft chain listed in the Summary.
- **Fix:** Move the session to an `HttpOnly; Secure; SameSite=Strict` cookie
  (`__Host-` prefixed), leaving the page non-token-aware; if the SPA must
  hold a token, hold a short-lived, narrowly-scoped one and keep the
  long-lived credential server-side.
- **References:** OWASP A02/A07; auth-review session-storage guidance.

### SEC-004: No Content-Security-Policy — MEDIUM (Possible — needs verification)
- **Where:** `index.html:3-6` (head — no CSP meta present)
- **CWE:** CWE-693 (Protection Mechanism Failure)
- **Evidence:** The document head contains no
  `<meta http-equiv="Content-Security-Policy" ...>`; server response headers
  are not visible from the repo (no server config exists).
- **Impact:** No script-src constraint means an XSS (SEC-001) executes
  unrestricted — no inline-script barrier, no report surface. CSP would not
  fix SEC-001 but would bound its blast radius.
- **Fix:** Add a nonce-based CSP (`script-src 'self' 'nonce-…'`) at the
  server or meta level; verify actual response headers once the hosting
  layer exists.
- **References:** config-hardening CSP rules.

## What looks good
- `safe-index.html` demonstrates the correct pattern and should be treated
  as the reference implementation: explicit `ALLOWED_ORIGIN` check
  (`safe-index.html:9`), `textContent` sink (`:10`), explicit
  non-wildcard target with a non-sensitive payload (`:13`).
- No secrets, no third-party scripts (zero external script/iframe
  references in either page — the supply-chain surface is empty), no
  network calls.

## What would make this worse (almost-chains)
- Any future addition of `eval`/remote script + SEC-001 would escalate to
  persistent script execution; keep the page dependency-free as it is now.
- If this page is ever served from the same origin as the main app, SEC-001
  becomes same-origin XSS against the app itself (cookie scope widens).

## OWASP completeness gate
A01 (no server surface) — not assessed; A02 — SEC-002/003; A03 — SEC-001;
A04 — embed trust model covered by SEC-001/002; A05 — SEC-004;
A06 — no dependency manifests, N/A; A07 — token handling SEC-002/003;
A08 — no integrity-sensitive imports, N/A; A09 — no logging surface, N/A;
A10 — no server-side fetching, N/A.

## Recommended fix order
1. SEC-001 (Critical, S) — origin check + textContent sink; the one change that removes the takeover path.
2. SEC-002 (High, S) — drop the token from postMessage; explicit target origin.
3. SEC-003 (Medium, M) — migrate session to HttpOnly `__Host-` cookie.
4. SEC-004 (Medium, S) — add CSP once hosting exists; verify headers.
