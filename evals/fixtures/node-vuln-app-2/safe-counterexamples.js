// SAFE counter-examples for node-vuln-app-2. An audit must NOT report these
// (they may appear under "What looks good"). See expected-findings.md.
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const { MongoClient } = require('mongodb');
const { Server } = require('socket.io');

const app = express();
const db = new MongoClient('mongodb://mongo.internal.example.com:27017').db('shop');

// SAFE (vs SEC-01): operator-stripping sanitizer before the query
function stripOperators(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k.startsWith('$')) continue;
    out[k] = v && typeof v === 'object' && !Array.isArray(v) ? stripOperators(v) : v;
  }
  return out;
}

app.post('/login-safe', async (req, res) => {
  const { email, password } = stripOperators(req.body);
  if (typeof email !== 'string' || typeof password !== 'string') return res.status(400).end();
  const user = await db.collection('users').findOne({ email, password }); // no operators survive
  res.status(user ? 200 : 401).json({ ok: !!user });
});

// SAFE (vs SEC-02): allowlist-picked fields into a fresh object — user keys never reach a target
let flags = { maintenance: false, paymentProvider: 'stripe' };

app.post('/settings-safe', (req, res) => {
  const { maintenance, paymentProvider } = req.body || {};
  if (typeof maintenance === 'boolean' && typeof paymentProvider === 'string') {
    flags = { ...flags, maintenance, paymentProvider };
  }
  res.json({ ok: true });
});

// SAFE (vs SEC-03): bounded input + single non-nested quantifier
app.get('/validate-safe', (req, res) => {
  const token = String(req.query.token || '');
  if (token.length > 64) return res.status(400).send('too long');
  if (!/^[a-z0-9]+$/.test(token)) return res.status(400).send('bad');
  res.send('ok');
});

// SAFE (vs SEC-04): exact allowlist of destinations
const SAFE_NEXT = new Set(['/dashboard', '/']);

app.get('/logout-safe', (req, res) => {
  const next = req.query.next || '/dashboard';
  res.redirect(SAFE_NEXT.has(next) ? next : '/dashboard');
});

// SAFE (vs SEC-05): header used for logging only, never as an identity/authz input
app.use((req, _res, next) => {
  console.log('request id:', req.headers['x-request-id']);
  next();
});

// SAFE (vs SEC-06): atomic conditional write — the guard and the claim are one operation
app.post('/coupon/redeem-safe', async (req, res) => {
  const result = await db
    .collection('coupons')
    .findOneAndUpdate({ code: req.body.code, used: false }, { $set: { used: true } });
  if (!result) return res.status(409).send('unknown or already used');
  res.send('redeemed');
});

// SAFE (vs SEC-07): MIME+ext allowlist, random filename, stored outside the webroot, size cap
const ALLOWED_EXT = new Set(['.png', '.jpg', '.jpeg']);
const uploadSafe = multer({
  storage: multer.diskStorage({
    destination: 'var/uploads', // NOT under express.static
    filename: (req, file, cb) =>
      cb(null, crypto.randomBytes(16).toString('hex') + path.extname(file.originalname).toLowerCase()),
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) =>
    cb(null, ALLOWED_EXT.has(path.extname(file.originalname).toLowerCase())),
});

app.post('/upload-safe', uploadSafe.single('avatar'), (req, res) => {
  res.json({ ok: true });
});

// SAFE (vs SEC-08): handshake auth + ownership check on subscribe
const ioSafe = new Server();

ioSafe.use((socket, next) => {
  try {
    socket.user = verifyJwt(socket.handshake.auth.token); // throws on bad token
    next();
  } catch (e) {
    next(new Error('unauthorized'));
  }
});

ioSafe.on('connection', (socket) => {
  socket.on('orders:subscribe', async (userId) => {
    if (socket.user.id !== userId && !socket.user.isAdmin) return; // ownership check
    socket.emit('orders', await db.collection('orders').find({ userId }).toArray());
  });
});

function verifyJwt(token) {
  /* FAKE stub — throws on invalid */
  if (!token) throw new Error('no token');
  return { id: 'user-1', isAdmin: false };
}
