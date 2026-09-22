# course-vuln-app — Expected findings

Ground truth for `evals/fixtures/course-vuln-app` (course-platform-security
skill — persona-driven: public/student/admin).

| # | Persona | Class | Finding | Where | Severity |
|---|---|---|---|---|---|
| 1 | public | GATING | catalog returns draft + private courses — no status/visibility filter | app.js:29-31 | High |
| 2 | public | PREVIEW | preview endpoint returns FULL lesson list (paid content free) | app.js:34-39 | Critical |
| 3 | student | ENROLLMENT | self-enrollment for any course/user with no paid-order artifact; userId from body | app.js:42-49 | Critical |
| 4 | student | COHORT | materials route has NO enrollment check and NO cohort scope — cross-cohort + non-student read; cohort from query | app.js:52-58 | Critical |
| 5 | public | ADMIN | `POST /api/admin/courses` without auth or role check — anyone publishes courses/sets prices | app.js:60-66 | Critical |

## Must NOT trigger (near-misses — `safe-platform.js`)

- Catalog filtered by `status === 'published' && visibility === 'public'`
- Preview sliced to `previewLessons`
- Enrollment only from the paid-order fulfillment path (status-guarded, user-matched)
- Materials scoped by the caller's enrollment record (cohort from enrollment, not query)
- Admin route with `requireAuth, requireAdmin`
