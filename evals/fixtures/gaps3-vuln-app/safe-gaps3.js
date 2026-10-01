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

// ---------- safe shapes: webhook verification + email-change re-auth ----------
const crypto = require('crypto');

function verifyBillingSignature(req) {
  const expected = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET)
    .update(req.rawBody) // RAW bytes, not re-parsed JSON
    .digest('hex');
  const provided = req.get('x-billing-signature') || '';
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
}

// SAFE: sender-authenticated webhook + replay window before any side effect
app.post('/webhooks/billing', requireSignature(verifyBillingSignature), withinReplayWindow('5m'), async (req, res) => {
  const event = req.body;
  if (event.type === 'invoice.paid') {
    await grantEntitlement(event.data.account_id, event.data.plan);
  }
  res.json({ received: true });
});

// SAFE: email change behind password re-auth + verify-before-swap
app.post('/account/email', requireAuth, requireCurrentPassword, async (req, res) => {
  const pending = await startEmailChange(req.user.id, req.body.email); // verification mail to the NEW address
  notifyOldAddress(req.user.email);
  res.json({ pending: pending.id });
});

// ---------- safe shapes: one-time codes ----------
function generateLoginCode() {
  return crypto.randomInt(0, 1000000).toString().padStart(6, '0'); // CSPRNG
}

// SAFE: code sent only to the STORED record's channel; response carries no code
app.post('/auth/email/code', throttle({ key: 'email+ip', max: 3 }), async (req, res) => {
  const user = await db.users.findByEmail(req.body.email);
  if (!user) return res.json({ sent: true }); // existence-neutral
  const code = generateLoginCode();
  await codes.store(user.id, code, { ttl: '5m', maxAttempts: 5 });
  await mailer.sendMail({ to: user.email, subject: 'Login code', body: `Code: ${code}` });
  res.json({ sent: true });
});

// SAFE: verify is single-use, throttled, constant-time — NO static fallback
app.post('/auth/email/login', throttle({ key: 'ip', max: 10 }), async (req, res) => {
  const expected = await codes.consume(req.body.email); // single-use, expires
  if (!expected || !crypto.timingSafeEqual(Buffer.from(String(req.body.code)), Buffer.from(String(expected)))) {
    return res.status(401).json({ error: 'invalid code' });
  }
  const user = await db.users.findByEmail(req.body.email);
  issueSession(res, user);
  res.json({ ok: true });
});

// SAFE: unset/empty webhook secret REJECTS (fail closed) — never skips verification
app.post('/hooks/deploy/:stackId', async (req, res) => {
  const secret = process.env.DEPLOY_WEBHOOK_SECRET;
  if (!secret) return res.status(503).json({ error: 'deploy webhook secret is not configured' }); // fail closed
  const expected = crypto.createHmac('sha256', secret).update(req.rawBody).digest();
  const got = Buffer.from(String(req.headers['x-deploy-signature'] || ''), 'utf8');
  if (!crypto.timingSafeEqual(got, expected)) return res.status(401).end();
  return res.json({ redeployed: true, stack: req.params.stackId });
});

// SAFE (vs SEC-15): guard mounted on the route path — router matching and
// dispatch share the DECODED path, so percent-encoded spellings cannot split
// the check from the route; req.url/originalUrl never read in any authz decision
function requireAdminToken(req, res, next) {
  if (!req.headers['x-admin-token']) return res.status(403).json({ error: 'admin only' });
  next();
}
app.use('/admin', requireAdminToken);
app.get('/admin/users', (req, res) => {
  res.json(db.users || []);
});

// SAFE (vs SEC-16): setup routes verify installation state server-side and
// refuse once installed — the first-run window closes after bootstrap, and
// restore takes an archive id, never raw SQL from the request body
function requireSetupMode(req, res, next) {
  if (db.meta.get('installed')) return res.status(403).json({ error: 'already installed' });
  next();
}
app.post('/setup/restore', requireSetupMode, (req, res) => {
  db.restoreArchive(req.body.archiveId);
  res.json({ restored: true });
});

// SAFE (vs SEC-17): devices authenticate with an enrolled per-device secret
// (one-time enrollment token at first contact); hostname is lookup/display only
app.post('/api/devices/login', async (req, res) => {
  const device = await db.devices.verifySecret(req.body.deviceId, req.body.deviceSecret);
  if (!device) return res.status(401).json({ error: 'invalid credentials' });
  issueSession(res, { type: 'device', id: device.id });
});
