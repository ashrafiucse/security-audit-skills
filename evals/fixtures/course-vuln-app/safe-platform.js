// SAFE counter-examples for course-vuln-app. An audit must NOT report these.
const express = require('express');
const app = express();
app.use(express.json());

const db = { courses: [], cohorts: [], enrollments: [], orders: [] };

function requireAuth(req, res, next) {
  if (!req.headers.authorization) return res.status(401).end();
  req.user = { id: req.headers.authorization.slice(7), role: 'student' };
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).end();
  next();
}

// SAFE (vs SEC-01): public catalog filters status AND visibility
app.get('/api/courses', (req, res) => {
  res.json(db.courses.filter((c) => c.status === 'published' && c.visibility === 'public'));
});

// SAFE (vs SEC-02): preview returns only the first N lessons
app.get('/api/courses/:id/preview', (req, res) => {
  const course = db.courses.find((c) => c.id === req.params.id && c.status === 'published');
  if (!course) return res.status(404).end();
  res.json({ title: course.title, lessons: course.content.slice(0, course.previewLessons) });
});

// SAFE (vs SEC-03): enrollment granted ONLY from a paid order (flow-terminal)
app.post('/api/fulfillment/order-paid', requireAuth, (req, res) => {
  const order = db.orders.find((o) => o.id === req.body.order_id && o.status === 'paid' && o.userId === req.user.id);
  if (!order) return res.status(409).end();
  db.enrollments.push({ userId: order.userId, courseId: order.courseId, cohortId: order.cohortId });
  res.status(201).end();
});

// SAFE (vs SEC-04): materials scoped by the CALLER's enrollment + cohort
app.get('/api/courses/:id/materials', requireAuth, (req, res) => {
  const enrollment = db.enrollments.find(
    (e) => e.userId === req.user.id && e.courseId === req.params.id
  );
  if (!enrollment) return res.status(403).end();
  const course = db.courses.find((c) => c.id === req.params.id);
  res.json({ lessons: course.content, cohortId: enrollment.cohortId });
});

// SAFE (vs SEC-05): admin route with auth + role middleware
app.post('/api/admin/courses', requireAuth, requireAdmin, (req, res) => {
  db.courses.push({ ...req.body, status: 'draft' });
  res.status(201).end();
});
