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

// ---------- safe shapes: flag gating + F9 amplification (incident conversion) ----------
const PLAN_CAPABILITIES = { trial: [], paid: ['send-email', 'import-leads'] };

function isCapabilityEnabled(flag, tenant) {
  return (PLAN_CAPABILITIES[tenant.plan] || []).includes(flag);
}

// SAFE: the handler is the enforcement point — flag middleware + rate limit + validated payload
app.post('/admin/leads/email/compose', requireAuth, requireFlag('send-email'), rateLimit('blast-compose'), (req, res) => {
  const dto = composeSchema.parse(req.body);
  queue.enqueue('email-blast', dto);
  res.json({ queued: true });
});

// SAFE: atomic quota inside the job + capped + verified-only recipients
queue.process('email-blast', async (job) => {
  if (!consumeBlastQuota(job.tenantId)) return;
  const leads = await db.leads.findAll({ where: { verified: true }, limit: 500 });
  for (const lead of leads) {
    await mailer.sendMail({ to: lead.email, subject: job.data.subject });
  }
});

// SAFE: POST + signed + throttled verification sender
app.post('/leads/:id/send-verification-link', requireSigned, throttle({ key: 'lead+ip', max: 3 }), async (req, res) => {
  const lead = await db.leads.findById(req.params.id);
  await mailer.sendMail({ to: lead.email, subject: 'Verify your email', body: verifyLink(lead) });
  res.json({ sent: true });
});
