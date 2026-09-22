# CourseForge — hardened spec (SAFE counter-example — must NOT produce threats)

Same product, controls specified at design time. An audit must NOT report these.

## 1. Catalog & discovery
Every PUBLIC read path (list, detail, facets, counts, sitemap) filters
`status = published AND visibility = public`. Staff preview unpublished
drafts only from a role-middleware-guarded admin surface, never the
public catalog.

## 2. Free preview
The preview endpoint returns ONLY the first N lessons, N set server-side;
the response is built by field selection (lesson titles + sample media),
never the full content array.

## 3. Student reviews
Review bodies are stored raw but EVERY render path escapes first: staff
detail view renders `e(body)` then applies line-break formatting; the
public page renders as plain text. Purification-at-write is the
alternative; either control satisfies the criterion.

## 4. Payments & access
The PayGate webhook requires signature verification before any state
write; replayed event ids are rejected. Enrollment is created only by
this status-guarded fulfillment path or by an admin-grant route with
role middleware.

## 5. Cohorts
Materials are scoped by the CALLER's enrollment record (cohort from the
enrollment, never from the request). Support staff inspect other cohorts
through a separate role-guarded endpoint.

## 6. Support
Display names are stored and rendered escaped everywhere; agents reply
as plain text.
