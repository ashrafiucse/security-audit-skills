// SAFE counter-examples for node-vuln-app-3. An audit must NOT report these.
const express = require('express');
const { execFile } = require('child_process');
const path = require('path');
const knex = require('knex')({ client: 'pg', connection: 'postgres://db.internal.example.com/shop' });

const app = express();

function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).end();
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.isAdmin) return res.status(403).end();
  next();
}

// SAFE (vs SEC-01): escaped read path — <%= %> auto-escapes the stored field
app.get('/profile-safe', requireAuth, async (req, res) => {
  const user = await knex('users').where({ id: req.session.userId }).first();
  res.render('profile', { user }); // template uses <%= user.bio %>
});

// SAFE (vs SEC-02): census row has both guards
app.get('/admin/billing', requireAuth, requireAdmin, async (_req, res) => {
  res.json(await knex('invoices').select('id', 'total'));
});

// SAFE (vs SEC-03): identifier binding (??) — no string concat at the raw boundary
const ORDERABLE = new Set(['name', 'price', 'created_at']);

app.get('/products-safe', async (req, res) => {
  const col = ORDERABLE.has(String(req.query.order)) ? String(req.query.order) : 'name';
  res.json(await knex.raw('SELECT * FROM products ORDER BY ??', [col]));
});

// SAFE (vs SEC-05): argument-array exec + validated, resolved, contained path
const UPLOAD_ROOT = '/srv/uploads';

queue.process = (job) => {
  const rel = path.normalize(String(job.data.path || '')).replace(/^(\.\.[/\\])+/, '');
  const abs = path.join(UPLOAD_ROOT, rel);
  if (!abs.startsWith(UPLOAD_ROOT + path.sep)) return job.done();
  execFile('convert', [abs, '/tmp/out.png'], () => job.done());
};

app.listen(3001);
