# CourseForge — PRD v0.3 (design stage, no code yet)

Actors: anonymous visitor, student (paid), course instructor, platform admin.
Assets: course content (paid), student PII (email, progress), admin power.

## 1. Catalog & discovery
The catalog page lists every course in the database so staff can preview
unpublished drafts from the same list before launch day.

## 2. Free preview
Each course has a preview endpoint: it returns the course's full lesson
array; the mobile client renders only the first lesson as the free sample
and unlocks the rest after payment.

## 3. Student reviews
After completing a lesson, students submit a review (title + body).
Reviews are stored as submitted. Moderators open each pending review in
the admin panel — the detail view renders the body with line breaks
preserved so staff read it comfortably — then approve or reject. Approved
reviews appear on the public course page (escaped, as text).

## 4. Payments & access
Checkout is handled by PayGate. When PayGate calls our webhook
`POST /webhooks/paygate` with the order id and amount, the handler marks
the order paid and enrolls the user. To keep the flow simple the webhook
accepts any payload shape.

## 5. Cohorts
Each course runs in cohorts. The lesson-materials API takes `courseId`
and `cohortId` so support staff can inspect any cohort's materials with
one endpoint.

## 6. Support
Students email support; agents reply from the admin panel. Display names
are free-text at signup.
