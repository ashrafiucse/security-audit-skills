# Security Audit — course-vuln-app
Date: 2026-09-23 | Scope: working tree (fixture) | Auditor: security-skills dev (IN-PROCESS run — see scoreboard label)

## Stack
Node/Express course platform (app.js + safe-platform.js variant). Actors: public/anonymous, student, admin (requireAuth exists; requireAdmin only in safe variant). Surfaces: public catalog, preview, enrollment, materials, admin courses, review submission, admin moderation detail.

## Summary
| Severity | Count |
|---|---|
| Critical | 5 |
| High | 1 |

## Findings
### SEC-001: Catalog gating — draft/private courses exposed publicly — HIGH
- **Where:** `app.js:29-31` — **CWE-200** — `res.json(db.courses)` unfiltered; `Secret Launch` (draft/private) leaks.

### SEC-002: Preview returns FULL lesson array — CRITICAL
- **Where:** `app.js:34-39` — **CWE-200/668** — paid content free; client-side gating only.

### SEC-003: Self-enrollment without paid-order artifact — CRITICAL
- **Where:** `app.js:42-49` — **CWE-840** — any user enrolls in any course; `userId` from body.

### SEC-004: Materials without enrollment check or cohort scope — CRITICAL
- **Where:** `app.js:52-58` — **CWE-639/668** — cross-cohort read; `cohort_id` from query; non-students read everything.

### SEC-005: Admin course publish without auth/role — CRITICAL
- **Where:** `app.js:60-66` — **CWE-862** — anyone publishes courses/sets prices.

### SEC-006: Moderation-queue XSS → staff account takeover — CRITICAL
- **Where:** `app.js:70-86` (write path :70-76, render sink :86)
- **CWE:** CWE-79 (stored) + CWE-269
- **Evidence:** review stored raw (length check only, :71-75) → `res.send(`<div class="mod-review">${r.body}</div>`)` in the ADMIN detail endpoint (:86) with `Content-Type: text/html` — unprivileged author, privileged viewer; `pending` status guarantees staff opens it.
- **Impact:** staff-origin XSS → session riding → admin ATO.
- **Fix:** escape at the render sink (safe-platform.js:62 `escapeHtml(r.body)` is the safe shape) or render as JSON/text.

## What looks good
- safe-platform.js: catalog filter, preview slice, paid-order fulfillment, enrollment-scoped materials, role-guarded admin, escaped moderation render.

## Coverage matrix (actor × surface)
| Surface ↓ · Actor → | public | student | staff/mod | admin |
|---|---|---|---|---|
| Catalog | ✅ SEC-001 | n/a | n/a | n/a |
| Preview | ✅ SEC-002 | n/a | n/a | n/a |
| Enrollment | n/a | ✅ SEC-003 | n/a | n/a |
| Materials | n/a | ✅ SEC-004 | n/a | n/a |
| Admin publish | ✅ SEC-005 (unguarded) | ✅ SEC-005 | n/a | n/a |
| Review write | n/a | ✅ SEC-006 (write half) | n/a | n/a |
| Moderation detail | n/a | n/a | ✅ SEC-006 (render half) | 🟢 safe variant escapes (safe-platform.js:62) |

## Not assessed
(none — all censused surfaces dispositioned)

## Census receipts
| Census | hits | dispositioned |
|---|---|---|
| route census (app.*) | 7 | 7 |
| HTML render sinks (res.send/sendStatus) | 2 | 2 (app.js:86 finding; safe:62 verified-safe) |

## Recommended fix order
1. SEC-006 escape render (S) → 2. SEC-005 + SEC-003 authz/state guards (M) → 3. SEC-004 cohort scoping (M) → 4. SEC-002 field-limited preview (S) → 5. SEC-001 catalog filter (S).
