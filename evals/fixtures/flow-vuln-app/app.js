// Fixture: business-flow vulnerabilities. FAKE data only.
// Each endpoint is individually defensible (auth present, parameterized
// queries) — the compromise only exists across the flow
// order -> payment -> invoice. Safe forms in safe-flow.js.
// Expected findings: see expected-findings.md
const express = require('express');
const app = express();
app.use(express.json());

const db = {
  orders: [],
  payments: [],
  invoices: [],
  users: [{ id: 'u1', name: 'alice' }, { id: 'u2', name: 'bob' }],
};

function requireAuth(req, res, next) {
  if (!req.headers.authorization) return res.status(401).end();
  req.user = { id: req.headers.authorization.slice(7) };
  next();
}

// FLOW: POST /orders -> POST /orders/:id/pay (gateway) -> POST /payments/webhook
//       -> POST /invoices  -> GET /invoices?order_id=

app.post('/orders', requireAuth, (req, res) => {
  const items = req.body.items || [];
  // F-07: float math for money at the boundary step
  const total = items.reduce((sum, i) => sum + i.price * i.qty, 0);
  const order = { id: 'o' + (db.orders.length + 1), userId: req.user.id, items, total, status: 'cart' };
  db.orders.push(order);
  res.json(order);
});

app.put('/orders/:id', requireAuth, (req, res) => {
  // F-06: order mutable with NO status guard — editable after payment
  const order = db.orders.find((o) => o.id === req.params.id && o.userId === req.user.id);
  if (!order) return res.status(404).end();
  Object.assign(order, req.body); // replace items/total freely, any status
  res.json(order);
});

app.post('/orders/:id/pay', requireAuth, (req, res) => {
  const order = db.orders.find((o) => o.id === req.params.id && o.userId === req.user.id);
  if (!order) return res.status(404).end();
  const payment = { id: 'p' + (db.payments.length + 1), orderId: order.id, amount: order.total, status: 'pending' };
  db.payments.push(payment);
  // gateway.charge(payment) — FAKE
  res.json(payment);
});

app.post('/payments/webhook', (req, res) => {
  // F-08: gateway callback with no signature/verification — spoofable hop
  const payment = db.payments.find((p) => p.id === req.body.payment_id);
  if (!payment) return res.status(404).end();
  payment.status = 'paid';
  const order = db.orders.find((o) => o.id === payment.orderId);
  order.status = 'paid'; // transition guarded only by spoofable webhook
  res.json({ ok: true });
});

app.post('/invoices', requireAuth, (req, res) => {
  // F-05/F-01: no status precondition — invoice a 'cart' order, or one with no
  // payment at all; no replay guard either
  const order = db.orders.find((o) => o.id === req.body.order_id);
  if (!order) return res.status(404).end();
  // F-03: no ownership check through the join — any user invoices any order
  // F-02: total is CLIENT-SUPPLIED at the terminal step, not from the order row
  const invoice = {
    id: 'i' + (db.invoices.length + 1),
    orderId: order.id,
    userId: req.user.id,
    total: req.body.total ?? order.total,
    issuedAt: Date.now(),
  };
  db.invoices.push(invoice); // F-04: no uniqueness on orderId/payment — replays duplicate
  res.status(201).json(invoice);
});

app.get('/invoices', requireAuth, (req, res) => {
  // F-03b: fetch by order_id with NO join to order.userId — cross-user read
  const invoices = db.invoices.filter((i) => i.orderId === req.query.order_id);
  res.json(invoices);
});

app.listen(3000);
