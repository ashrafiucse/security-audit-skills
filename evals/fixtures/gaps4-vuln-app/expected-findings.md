# gaps4-vuln-app — Expected findings

Adversarial-drill fixture (injection-flaws red-team): every planted bug
phrased to DEFEAT the skill's documented greps as they existed pre-drill;
every triage form is designed to FIRE the greps while being safe.

| # | Class | Finding | Where | Severity |
|---|---|---|---|---|
| 1 | XSS (unknown sink) | `insertAdjacentHTML('beforeend', comment.body)` — raw HTML sink the pre-drill pattern library didn't list; comment.body is other-user input rendered into the feed | app.js:14 | High |
| 2 | XSS (unknown sink) | `bioEl.outerHTML = user.profile.bio` — assignment sink; parsed as HTML, user-authored bio | app.js:19 | High |
| 3 | SQLi (split construction) | SELECT literal and the tainted `+` live on DIFFERENT lines (`base` then `pool.query(base + req.params.ref)`) — both single-line SQLi greps walk past it; call-site grep (`query(var + …`) is required | app.js:27-28 | Critical |
| 4 | Command injection (shell re-parse) | `spawn('git', ['log', '--oneline', userBranch], { shell: true })` — the arg ARRAY is not a defense when `shell: true` re-parses it; userBranch is shell metachar-reachable | app.js:35 | High |

## Must NOT trigger (near-misses — triage-gaps4.js fires-but-safe, falsifier documented)

- triage-gaps4.js:10 `feed.innerHTML = DOMPurify.sanitize(post.content)` — sanitizer that counts (skill's own list); falsifier: "DOMPurify.sanitize precedes assignment"
- triage-gaps4.js:14 `innerHTML = ''` — clearing; no input reaches the sink
- triage-gaps4.js:20 `innerHTML = VERIFIED_BADGE_SVG` — code-owned constant, zero user input
- app.js:10-11 — comment-text mentions of `innerHTML`/`document.write`; grep hit is legitimate, disposition = documentation noise, not a sink
- safe-gaps4.js — parameterized query (`?` + args array), `textContent` assignment, `execFile` arg-array without shell

## Out of ground truth (informational)

- `express`/`child_process` dependency versions (unpinned, code-pattern fixture)
