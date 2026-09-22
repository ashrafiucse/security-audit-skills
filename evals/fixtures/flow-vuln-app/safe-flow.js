// SAFE counter-examples for flow-vuln-app. An audit must NOT report these.
const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

const db = {
  orders: [],
  payments: [],
  invoices: [],
};

function requireAuth(req, res, next) {
  if (!req.headers.authorization) return res.status(401).end();
  req.user = { id: req.headers.authorization.slice(7) };
  next();
}

const money = (cents) => Math.round(cents); // SAFE (vs F-07): integer minor units everywhere

app.post('/orders', requireAuth, (req, res) => {
  const items = (req.body.items || []).map((i) => ({ sku: i.sku, qty: i.qty, unitCents: i.unitCents }));
  const totalCents = items.reduce((sum, i) => sum + money(i.unitCents * i.qty), 0);
  db.orders.push({ id: 'o' + (db.orders.length + 1), userId: req.user.id, items, totalCents, status: 'cart' });
  res.status(201).end();
});

app.put('/orders/:id', requireAuth, (req, res) => {
  // SAFE (vs F-06): frozen at the payment boundary
  const order = db.orders.find((o) => o.id === req.params.id && o.userId === req.user.id);
  if (!order) return res.status(404).end();
  if (order.status !== 'cart') return res.status(409).json({ error: 'order locked after payment' });
  order.items = req.body.items;
  res.json(order);
});

app.post('/payments/webhook', (req, res) => {
  // SAFE (vs F-08): HMAC-verified gateway callback
  const sig = crypto.createHmac('sha256', process.env.GATEWAY_SECRET).update(req.rawBody).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(req.headers['x-signature'] || ''))) {
    return res.status(401).end();
  }
  const payment = db.payments.find((p) => p.id === req.body.payment_id);
  if (payment) payment.status = 'paid';
  res.json({ ok: true });
});

app.post('/invoices', requireAuth, (req, res) => {
  // SAFE (vs F-01/02/03/05): status precondition + ownership join +
  // server-derived total + replay guard
  const order = db.orders.find((o) => o.id === req.body.order_id && o.userId === req.user.id);
  if (!order) return res.status(404).end();
  if (order.status !== 'paid') return res.status(409).json({ error: 'not paid' }); // skip/disorder blocked
  if (db.invoices.some((i) => i.orderId === order.id)) return res.status(409).json({ error: 'already invoiced' }); // replay blocked
  const invoice = { orderId: order.id, userId: req.user.id, totalCents: order.totalCents }; // from the persisted row
  db.invoices.push(invoice);
  res.status(201).json(invoice);
});

app.get('/invoices', requireAuth, (req, res) => {
  // SAFE (vs F-03b): ownership verified THROUGH the join
  const order = db.orders.find((o) => o.id === req.query.order_id && o.userId === req.user.id);
  if (!order) return res.status(404).end();
  res.json(db.invoices.filter((i) => i.orderId === order.id));
});
