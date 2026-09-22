// Fixture: intentionally vulnerable Node/Express app — part 2. FAKE data only.
// Covers classes not in node-vuln-app: NoSQL operator injection, prototype
// pollution, ReDoS, open redirect, trusted-header authz, TOCTOU race, unsafe
// upload, WebSocket authz. Safe counter-examples live in safe-counterexamples.js.
// Expected findings: see expected-findings.md
const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const multer = require('multer');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.urlencoded({ extended: true })); // deep-parsed bodies: pollution source
app.use(express.static('public')); // webroot — see /upload below

const client = new MongoClient('mongodb://mongo.internal.example.com:27017');
const db = client.db('shop');
const io = new Server(http.createServer(app));

// ---------- NoSQL operator injection ----------
app.post('/login', async (req, res) => {
  // SEC-01: request fields pass straight into the query — {"password":{"$ne":""}} logs you in
  const user = await db
    .collection('users')
    .findOne({ email: req.body.email, password: req.body.password });
  if (user) return res.json({ ok: true, role: user.role });
  res.status(401).json({ ok: false });
});

// ---------- Prototype pollution ----------
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = deepMerge(target[key] || {}, source[key]); // __proto__ walks into the prototype
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

const featureFlags = { maintenance: false, paymentProvider: 'stripe' };

app.post('/settings', async (req, res) => {
  // SEC-02: user-controlled KEYS deep-merged into an existing object → Object.prototype pollution
  deepMerge(featureFlags, req.body);
  res.json({ ok: true });
});

// ---------- ReDoS ----------
app.get('/validate', (req, res) => {
  // SEC-03: nested quantifier on unbounded user input — /^(a+)+$/ vs "a".repeat(40)+"!"
  if (!/^(a+)+$/.test(req.query.token)) return res.status(400).send('bad');
  res.send('ok');
});

// ---------- Open redirect ----------
app.get('/logout', (req, res) => {
  // SEC-04: attacker-controlled redirect target
  res.redirect(req.query.next || '/');
});

// ---------- Trusted-header authorization ----------
app.get('/internal/orders', async (req, res) => {
  // SEC-05: identity taken from a spoofable header — no token, no session check
  const userId = req.headers['x-user-id'];
  const orders = await db.collection('orders').find({ userId }).toArray();
  res.json(orders);
});

// ---------- Check-then-act race (TOCTOU) ----------
app.post('/coupon/redeem', async (req, res) => {
  // SEC-06: single-use coupon — check and use are two steps; parallel replay wins
  const coupon = await db.collection('coupons').findOne({ code: req.body.code });
  if (!coupon) return res.status(404).send('unknown coupon');
  if (coupon.used) return res.status(409).send('already used');
  await db.collection('coupons').updateOne({ code: req.body.code }, { $set: { used: true } });
  await grantDiscount(coupon.amount);
  res.send('redeemed');
});

async function grantDiscount(amount) {
  /* credits the discount — FAKE */
}

// ---------- Unsafe file upload ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: 'public/uploads', // SEC-07b: stored under the served webroot
    filename: (req, file, cb) => cb(null, file.originalname), // SEC-07a: user filename verbatim
  }),
  // no fileFilter, no limits — SEC-07c
});

app.post('/upload', upload.single('avatar'), (req, res) => {
  res.json({ path: `/uploads/${req.file.originalname}` });
});

// ---------- WebSocket: no handshake auth, no subscription authz ----------
io.on('connection', (socket) => {
  // SEC-08: no io.use(auth) middleware anywhere — any client connects as anyone
  socket.on('orders:subscribe', async (userId) => {
    // SEC-08b: subscription without ownership check → IDOR over sockets
    const orders = await db.collection('orders').find({ userId }).toArray();
    socket.emit('orders', orders);
  });
});

app.listen(3000);
io.listen(3001);
