// Fixture: proactive gap classes — multi-tenant scoping, deferred SSRF via
// registered webhooks, archive extraction attacks, comparison hygiene.
// FAKE data only. Safe forms in safe-gaps3.js.
// Expected findings: see expected-findings.md
const express = require('express');
const AdmZip = require('adm-zip');
const fetch = require('node-fetch');

const app = express();
app.use(express.json());

const db = {
  users: [{ id: 'u1', tenantId: 'acme', name: 'alice' }, { id: 'u2', tenantId: 'globex', name: 'bob' }],
  reports: [
    { id: 'r1', tenantId: 'acme', data: 'acme-financials' },
    { id: 'r2', tenantId: 'globex', data: 'globex-financials' },
  ],
  hooks: [], // user-registered webhook URLs
};

function requireAuth(req, res, next) {
  if (!req.headers.authorization) return res.status(401).end();
  req.user = db.users.find((u) => u.id === req.headers.authorization.slice(7)) || {};
  next();
}

// ---------- SEC-01: multi-tenant unscoped read ----------
app.get('/api/reports', requireAuth, (req, res) => {
  // no tenantId filter — globex user receives acme financials (and vice versa)
  res.json(db.reports);
});

// tenant-scoped counterpart elsewhere (must NOT trigger): the pattern the
// census expects everywhere
app.get('/api/my-reports', requireAuth, (req, res) => {
  res.json(db.reports.filter((r) => r.tenantId === req.user.tenantId));
});

// ---------- SEC-02 + SEC-03: deferred SSRF via registered webhook ----------
app.post('/api/hooks', requireAuth, (req, res) => {
  // SEC-02: registration stores any URL — no scheme/host validation
  db.hooks.push({ userId: req.user.id, url: req.body.url });
  res.json({ ok: true });
});

function deliver(event) {
  // SEC-03: delivery job fetches stored URLs — internal ranges and cloud
  // metadata reachable; event payloads may carry secrets (exfil channel)
  db.hooks.forEach((h) => {
    fetch(h.url, { method: 'POST', body: JSON.stringify(event) }).catch(() => {});
  });
}

// ---------- SEC-04: archive extraction attacks ----------
app.post('/api/import', requireAuth, (req, res) => {
  const zip = new AdmZip(req.files.archive.data);
  // zip-slip: entry names with ../ escape the target; overwrite true clobbers
  zip.extractAllTo('/data/imports/' + req.user.id, true);
  res.json({ ok: true });
});

// ---------- SEC-05: comparison hygiene ----------
const ALLOWED_HOSTS = ['dashboard.example.com', 'api.example.com'];

app.get('/redirect', (req, res) => {
  const host = new URL(req.query.next).host;
  // raw substring match: subdomain tricks AND suffix tricks pass
  // ("evil-api.example.com.attacker.io"? no — but "api.example.com.evil.io" matches includes)
  if (ALLOWED_HOSTS.some((h) => host.includes(h))) {
    return res.redirect(req.query.next);
  }
  res.redirect('/');
});

app.listen(3000);
