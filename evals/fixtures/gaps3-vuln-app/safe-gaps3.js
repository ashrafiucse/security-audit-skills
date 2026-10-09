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

// SAFE (vs SEC-18): the capability check runs on the SESSION principal
// (req.user), and the revert target comes from server-side switch state —
// a forged cookie can name a user but proves nothing about the requester
app.post('/admin/switch/revert', requireAuth, async (req, res) => {
  if (!req.user || !req.user.can('manage_options')) return res.status(403).json({ error: 'not allowed' });
  const originalId = req.session.switch_original_id; // server-recorded switch state
  const original = await db.users.findById(originalId);
  if (!original) return res.status(404).json({ error: 'no switch in progress' });
  issueSession(res, { type: 'user', id: original.id });
});

// SAFE (vs SEC-19): the callback verifies the sender's signature FIRST and
// resolves the member from the VERIFIED event's stored order — identity never
// comes from a request parameter
app.post('/payment/paypal/callback', async (req, res) => {
  const event = verifyPaypalSignature(req.rawBody, req.headers['x-paypal-signature']);
  if (!event) return res.status(401).json({ error: 'bad signature' });
  const order = await db.orders.findById(event.order_id);
  req.login(await db.users.findById(order.user_id)); // identity from the verified record
  res.json({ status: 'ok' });
});

// SAFE (vs SEC-20): the command channel enforces a role check on the handler
// AND a server-side command allowlist before anything reaches the agent
io.on('connection', (socket) => {
  socket.on('agent:command', requireRole('operator'), async (msg) => {
    if (!AGENT_COMMANDS.has(msg.command)) return socket.emit('error', 'command not allowed');
    const agent = agents.byHostname(msg.hostname);
    agent.send({ cmd: msg.command }); // allowlisted verb, operator-only
  });
});

// SAFE (vs SEC-21): the internal key is honored ONLY on /internal routes,
// compared constant-time, and grants a scoped service identity — never admin
const INTERNAL_ROUTES = /^\/internal\//;
app.use((req, res, next) => {
  if (!INTERNAL_ROUTES.test(req.path)) return next();
  const expected = process.env.INTERNAL_KEY || '';
  const got = req.headers['x-internal-key'] || '';
  if (expected && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected))) {
    req.user = { id: 'svc:metrics', role: 'service', scope: ['metrics:read'] };
  }
  next();
// SAFE (vs SEC-22): linking requires the authenticated session AND a fresh
// primary factor (step-up), links to the session principal only, and takes
// the external identity from the IdP's VERIFIED assertion — never from a
// caller-supplied login_name/idp_user_id pair (ZITADEL CVE-2026-105207 safe
// shape)
app.post('/auth/link', requireAuth, requireStepUp, async (req, res) => {
  const assertion = await idp.verify(req.body.assertion); // IdP-signed, audience-checked
  await db.idpLinks.create({ user_id: req.user.id, idp_user_id: assertion.sub }); // session principal only
  res.json({ linked: true });
});

// SAFE (vs SEC-23): the target lookup itself is tenant-scoped — the query
// carries the caller's SESSION org (never a request header), so a target
// outside the caller's org is simply absent (ZITADEL CVE-2026-105209 safe
// shape: scoped query, not fetch-then-check)
app.post('/admin/enroll-code', requireAuth, async (req, res) => {
  const target = await db.users.findOne({ id: req.body.user_id, org_id: req.session.org_id });
  if (!target) return res.status(404).json({ error: 'no such user in your org' });
  const code = codes.issue(target.id, 'passkey'); // same-org target only
  res.json({ code });
});

// SAFE (vs SEC-24): the public whitelist is an EXACT path set — the
// namespace-scoped configs routes keep their token check (Kestra
// CVE-2026-49869 safe shape: anchored/exact match, never endsWith)
const PUBLIC_API_PATHS = new Set(['/configs']);
app.use('/api', (req, res, next) => {
  if (PUBLIC_API_PATHS.has(req.path)) return next(); // exact set membership
  if (!req.headers['x-api-token']) return res.status(401).json({ error: 'token required' });
  next();
});
app.get('/api/namespaces/:ns/configs', async (req, res) => {
  res.json(await db.namespaceConfigs(req.params.ns)); // token enforced above
});
