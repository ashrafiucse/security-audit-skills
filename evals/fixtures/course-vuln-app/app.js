// Fixture: course-platform vulnerabilities. FAKE data only.
// Planted per the three personas (public/student/admin) — see
// skills/course-platform-security. Safe forms in safe-platform.js.
// Expected findings: see expected-findings.md
const express = require('express');
const app = express();
app.use(express.json());

const db = {
  courses: [
    { id: 'c1', title: 'Public Course', status: 'published', visibility: 'public', content: ['l1', 'l2', 'l3'], previewLessons: 1 },
    { id: 'c2', title: 'Secret Launch', status: 'draft', visibility: 'private', content: ['l1', 'l2'], previewLessons: 0 },
  ],
  cohorts: [
    { id: 'ch1', courseId: 'c1', name: 'January' },
    { id: 'ch2', courseId: 'c1', name: 'February' },
  ],
  enrollments: [{ id: 'e1', userId: 'u1', courseId: 'c1', cohortId: 'ch1' }],
  orders: [],
};

function requireAuth(req, res, next) {
  if (!req.headers.authorization) return res.status(401).end();
  req.user = { id: req.headers.authorization.slice(7), role: 'student' };
  next();
}

// ---------- GATING (public persona) ----------
app.get('/api/courses', (req, res) => {
  // SEC-01: no status/visibility filter — draft + private courses in the public catalog
  res.json(db.courses);
});

// ---------- PREVIEW (public persona) ----------
app.get('/api/courses/:id/preview', (req, res) => {
  const course = db.courses.find((c) => c.id === req.params.id);
  if (!course) return res.status(404).end();
  // SEC-02: full content returned for a "preview" — paid lessons free
  res.json({ title: course.title, lessons: course.content });
});

// ---------- ENROLLMENT state machine (student persona) ----------
app.post('/api/enrollments', requireAuth, (req, res) => {
  // SEC-03: self-enrollment for any course/user — no paid-order artifact,
  // no admin middleware; userId even taken from the body
  const enrollment = { id: 'e' + (db.enrollments.length + 1), userId: req.body.userId ?? req.user.id, courseId: req.body.courseId, cohortId: req.body.cohortId };
  db.enrollments.push(enrollment);
  res.status(201).json(enrollment);
});

// ---------- COHORT scoping (student persona) ----------
app.get('/api/courses/:id/materials', requireAuth, (req, res) => {
  const course = db.courses.find((c) => c.id === req.params.id);
  if (!course) return res.status(404).end();
  // SEC-04: no enrollment check at all, and no cohort scope — u1 (cohort ch1)
  // reads ch2's materials; non-students read everything
  res.json({ lessons: course.content, cohortId: req.query.cohort_id });
});

// ---------- ADMIN surface (should be admin-only) ----------
app.post('/api/admin/courses', (req, res) => {
  // SEC-05: no requireAuth, no role check — public persona publishes courses & sets prices
  const course = { id: 'c' + (db.courses.length + 1), ...req.body, status: 'published', visibility: 'public' };
  db.courses.push(course);
  res.status(201).json(course);
});

app.listen(3000);
