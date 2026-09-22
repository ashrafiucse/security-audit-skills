// Fixture: intentionally vulnerable Node/Express app — part 3. FAKE data only.
// Covers: route census (unguarded admin route among guarded ones), stored XSS
// (DB -> EJS read path), query-builder raw sink, multi-line query
// construction, queue-consumer command injection (second-order).
// Safe counter-examples live in safe-counterexamples.js.
// Expected findings: see expected-findings.md
const express = require('express');
const { exec } = require('child_process');
const knex = require('knex')({ client: 'pg', connection: 'postgres://db.internal.example.com/shop' });

const app = express();
app.set('view engine', 'ejs');

function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).end();
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.isAdmin) return res.status(403).end();
  next();
}

// ---------- Stored XSS (second-order: DB -> template read path) ----------
app.get('/profile', requireAuth, async (req, res) => {
  // SEC-01: bio was length-validated on WRITE; rendered unescaped on READ
  const user = await knex('users').where({ id: req.session.userId }).first();
  res.render('profile', { user }); // sink is in views/profile.ejs (<%- %>)
});

// ---------- Route census: the unguarded admin route ----------
app.get('/admin/users', async (req, res) => {
  // SEC-02: no requireAuth, no requireAdmin — found by census, not by luck
  const users = await knex('users').select('id', 'email', 'role');
  res.json(users);
});

app.get('/admin/settings', requireAuth, requireAdmin, async (req, res) => {
  // SAFE counterpart of SEC-02 (must NOT trigger): both guards present
  res.json(await knex('settings').first());
});

// ---------- Query-builder raw sink ----------
app.get('/products', async (req, res) => {
  // SEC-03: ORM does not save you at the raw boundary
  const rows = await knex.raw('SELECT * FROM products ORDER BY ' + req.query.order);
  res.json(rows);
});

// ---------- Multi-line query construction ----------
app.post('/orders/search', async (req, res) => {
  const status = req.body.status;
  // SEC-04: query assembled across lines — single-line greps walk past this
  const rows = await knex.raw(
    `SELECT id, total FROM orders
     WHERE status = '${status}'
       AND total > 0`
  );
  res.json(rows);
});

// ---------- Second-order command injection (queue consumer) ----------
const queue = [];

queue.process = (job) => {
  // SEC-05: worker trusts producer payload — producers are not a trust boundary
  exec(`convert ${job.data.path} /tmp/out.png`, () => job.done());
};

app.post('/jobs/resize', requireAuth, (req, res) => {
  queue.push({ data: req.body, done: () => {} });
  res.json({ queued: true });
});

// ---------- Mass assignment ----------
app.put('/users/me', requireAuth, async (req, res) => {
  // SEC-06: whole request body into update — role/isAdmin/credits settable by anyone
  await knex('users').where({ id: req.session.userId }).update(req.body);
  res.json({ ok: true });
});

app.listen(3000);
