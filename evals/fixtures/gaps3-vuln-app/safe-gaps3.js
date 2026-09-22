// SAFE counter-examples for gaps3-vuln-app. An audit must NOT report these.
const express = require('express');
const path = require('path');
const AdmZip = require('adm-zip');

const app = express();
const db = { reports: [], hooks: [] };

function requireAuth(req, res, next) {
  next();
}

// SAFE (vs SEC-01): every read scoped by the session tenant, not request data
app.get('/api/reports', requireAuth, (req, res) => {
  res.json(db.reports.filter((r) => r.tenantId === req.user.tenantId));
});

// SAFE (vs SEC-02/03): registration validates scheme+public host; delivery
// re-validates against resolved IP (metadata/private ranges blocked)
const HOST_OK = (h) => /^[\w.-]+\.example\.com$/.test(h) && !/-/.test(h.split('.')[0]);

app.post('/api/hooks', requireAuth, (req, res) => {
  const u = new URL(req.body.url);
  if (u.protocol !== 'https:' || !HOST_OK(u.host)) return res.status(400).end();
  db.hooks.push({ url: u.toString() });
  res.json({ ok: true });
});

// SAFE (vs SEC-04): every entry resolved+contained before extraction;
// symlink/absolute members rejected; no overwrite
function safeExtract(buffer, dest) {
  const zip = new AdmZip(buffer);
  for (const e of zip.getEntries()) {
    const target = path.resolve(dest, e.entryName);
    if (target !== dest && !target.startsWith(dest + path.sep)) throw new Error('zip-slip blocked');
    if (e.isSymbolicLink()) throw new Error('symlink member rejected');
  }
  zip.extractAllTo(dest, false);
}

// SAFE (vs SEC-05): parsed URL + exact host equality against allowlist
const ALLOWED = new Set(['dashboard.example.com', 'api.example.com']);

app.get('/redirect', (req, res) => {
  const u = new URL(req.query.next);
  if (u.protocol === 'https:' && ALLOWED.has(u.host)) return res.redirect(u.toString());
  res.redirect('/');
});
