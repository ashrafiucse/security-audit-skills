# Security Audit — flow-vuln-app
Date: 2026-09-22 | Scope: working tree (fixture @ commit 83fb015) | Auditor: security-skills v1.2.0-36-ge977d73-dirty → see note
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: NOT RUN (no network per audit constraints)

## Stack
Node/Express single-file app (`app.js`); in-memory object store (no DB driver,
no SQL, no templates, no child_process); sibling `safe-flow.js` is an explicit
safe counter-example file (not deployed, not reported on). One stateful flow:
`POST /orders → PUT /orders/:id → POST /orders/:id/pay → POST /payments/webhook
→ POST /invoices → GET /invoices?order_id=`. Bearer-style `requireAuth` on all
routes except the webhook. No dependency manifest, no infra files.

## Summary
| Severity | Count |
|---|---|
| Critical | 5 |
| High | 3 |
| Medium | 3 |
| Low | 0 |

**Chains (completed):** webhook-spoof → paid → invoice (free goods) ·
post-payment tamper + client-total (money theft) · F5+F3 (cross-user invoicing)

## Findings

### SEC-001: Invoice generation without any flow precondition — flow-F1/F5 — CRITICAL
- **Flow:** `POST /orders → (payment steps skipped) → POST /invoices`
- **Where:** `app.js:62-77`
- **CWE:** CWE-841 (Improper Enforcement of Behavioral Workflow)
- **Evidence:**
  ```js
  const order = db.orders.find((o) => o.id === req.body.order_id);
  if (!order) return res.status(404).end();
  ```
  The only precondition is that the order EXISTS. No `status === 'paid'`
  check, no payment-row existence check — the terminal money step trusts that
  earlier steps happened.
- **Impact:** Anyone authenticated invoices a `cart` order or an order with no
  payment at all (`POST /invoices {order_id: o1}` on a fresh order → 201).
  Invoice-before-payment also enables accounting/fulfillment fraud downstream.
- **Fix:** Guard the transition at the step that consumes it:
  ```js
  if (order.status !== 'paid') return res.status(409).json({error: 'not paid'});
  if (!db.payments.some(p => p.orderId === order.id && p.status === 'paid'))
    return res.status(409).json({error: 'no completed payment'});
  ```

### SEC-002: Client-supplied invoice total at the terminal step — flow-F2 — CRITICAL
- **Flow:** `order(total=server-derived) → payment(amount=order.total) → invoice(total=?)`
- **Where:** `app.js:73`
- **CWE:** CWE-602 (Client-Side Enforcement of Server-Side Security) / CWE-345
- **Evidence:**
  ```js
  total: req.body.total ?? order.total,
  ```
  The invoice records whatever total the client sends; the persisted order row
  is only a fallback.
- **Impact:** Price tampering: order and payment say 100, invoice obediently
  records 1 (or 0, or negative). Any downstream consumer of the invoice
  (refunds, exports, accounting) is poisoned at the attacker's choosing.
- **Fix:** Money values at terminal steps derive from the persisted source of
  truth only: `total: order.total` — delete `req.body.total` from the shape.

### SEC-003: Association (chained) IDOR — any user invoices any order — flow-F3 — CRITICAL
- **Flow:** `alice creates order → bob POST /invoices {order_id: alice's}`
- **Where:** `app.js:64` (create) and `app.js:80-83` (read)
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Evidence:**
  ```js
  const order = db.orders.find((o) => o.id === req.body.order_id);   // :64 — no userId predicate
  ...
  const invoices = db.invoices.filter((i) => i.orderId === req.query.order_id); // :82 — no join to order.userId
  ```
  Every OTHER order endpoint checks `o.userId === req.user.id` (app.js:36, :44) —
  each endpoint guards its own object; the invoice endpoints skip the join.
- **Impact:** Bob invoices himself against Alice's order (invoice issued to
  bob for alice's goods), and `GET /invoices?order_id=<any>` reads any user's
  invoices. Route-level audit of each endpoint individually misses exactly this.
- **Fix:** Verify ownership through the FULL association chain in both handlers:
  `o.id === req.body.order_id && o.userId === req.user.id`, and resolve the
  order (ownership-checked) before filtering invoices by it.

### SEC-004: Payment webhook unauthenticated and unsigned — flow-F8 — CRITICAL
- **Flow:** `POST /payments/webhook → order.status = 'paid'`
- **Where:** `app.js:52-60`
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-306
- **Evidence:**
  ```js
  app.post('/payments/webhook', (req, res) => {   // no requireAuth, no signature
    const payment = db.payments.find((p) => p.id === req.body.payment_id);
    ...
    order.status = 'paid';  // transition rests entirely on this hop
  ```
- **Impact:** The `paid` state — the trust boundary for invoicing — is written
  by an endpoint anyone on the network can call with any payment id. Combined
  with SEC-001/SEC-002 this is the "free goods" chain: spoof webhook →
  invoice at will.
- **Fix:** HMAC-verify the callback (`x-signature` via
  `crypto.timingSafeEqual` against `HMAC(gateway_secret, rawBody)`) and reject
  mismatches with 401; the payment id alone must never authorize the transition.

### SEC-005: Identity taken verbatim from the Authorization header — CRITICAL (Possible — needs verification)
- **Where:** `app.js:18-19`
- **CWE:** CWE-287 (Improper Authentication) / CWE-347
- **Evidence:**
  ```js
  if (!req.headers.authorization) return res.status(401).end();
  req.user = { id: req.headers.authorization.slice(7) };
  ```
  The bearer token IS the user id — no verification against any credential
  store. `Authorization: Bearer u2` becomes user u2.
- **Impact:** Total impersonation: every `userId === req.user.id` ownership
  check in the app collapses (orders, mutations, invoices). Likely an auth
  stub in this demo context, but as written it is an auth bypass.
- **Fix:** Validate the token (session lookup or JWT verify with pinned
  algorithm) and derive `req.user.id` from the VERIFIED claims — never from
  raw header bytes.

### SEC-006: Order mutable after payment — no status guard on PUT — flow-F6 — HIGH
- **Flow:** `order → pay → PUT /orders/:id → invoice reads tampered row`
- **Where:** `app.js:35-40`
- **CWE:** CWE-284 (Improper Access Control: state after trust boundary)
- **Evidence:**
  ```js
  app.put('/orders/:id', requireAuth, (req, res) => {
    const order = db.orders.find((o) => o.id === req.params.id && o.userId === req.user.id);
    if (!order) return res.status(404).end();
    Object.assign(order, req.body); // any status, any field
  ```
- **Impact:** Pay for a $10 order, replace items/total with a $1000 one after
  the payment boundary; invoice/fulfillment then reads attacker-chosen data.
  Chains with SEC-002 for full money theft.
- **Fix:** Freeze at the boundary: `if (order.status !== 'cart') return
  409 'order locked after payment'` (or version/cancel-and-recreate semantics).

### SEC-007: Invoice replay — no uniqueness on the flow's business key — flow-F4 — HIGH
- **Flow:** `POST /invoices (xN for the same order)`
- **Where:** `app.js:76`
- **CWE:** CWE-837 (Improper Enforcement of a Single, Unique Execution Point)
- **Evidence:**
  ```js
  db.invoices.push(invoice); // no check db.invoices.some(i => i.orderId === order.id)
  ```
- **Impact:** Webhook retries, double-clicks, or scripted replays mint
  duplicate invoices for one payment — duplicate credit/refund exposure,
  accounting corruption.
- **Fix:** Unique index on `invoices.orderId` (or payment id) + treat the
  conflict as 409; idempotency keys must be checked at the step that
  CONSUMES them.

### SEC-008: GET /invoices cross-user read (no ownership join) — flow-F3 — HIGH
- **Where:** `app.js:80-83`
- **CWE:** CWE-200 (Exposure of Sensitive Information) / CWE-639
- **Evidence:**
  ```js
  const invoices = db.invoices.filter((i) => i.orderId === req.query.order_id);
  res.json(invoices);
  ```
- **Impact:** Any authenticated user enumerates any order's invoices
  (`?order_id=o1..oN`) — totals, ids, issuance metadata.
- **Fix:** Resolve the order with the ownership predicate first; only then
  filter invoices by it. (Reported separately from SEC-003 because the fix
  lands in a different handler.)

### SEC-009: Float arithmetic for money at the boundary step — flow-F7 — MEDIUM
- **Flow:** `POST /orders` (total) → payment amount → invoice total
- **Where:** `app.js:29`
- **CWE:** CWE-1061 (Floating Point Comparison / monetary representation)
- **Evidence:**
  ```js
  const total = items.reduce((sum, i) => sum + i.price * i.qty, 0);
  ```
- **Impact:** Order-time float drift (10.005 vs 10.01 vs 10.00) vs charged
  vs invoiced amounts → refund/credit arbitrage and reconciliation breaks.
- **Fix:** Integer minor units (cents) end-to-end with a single rounding
  point, or Decimal; same representation at every step of the flow.

### SEC-010: No security headers / no rate limiting on flow endpoints — MEDIUM
- **Where:** `app.js:16` (middleware setup) — global
- **CWE:** CWE-693 (Missing Protection Mechanism)
- **Evidence:** Only `express.json()` middleware is registered — no helmet,
  no CSP/X-Frame-Options/nosniff, no rate limiter on the payment/invoice
  endpoints.
- **Impact:** Missing headers (clickjacking/MIME-sniffing surface) plus
  unthrottled money endpoints ease scripted replay of SEC-001/SEC-007.
- **Fix:** `helmet()` + rate limits on `/invoices` and `/payments/webhook`
  (per-IP and per-account) as defense in depth behind the flow fixes.

### SEC-011: No audit logging for payment/invoice operations — MEDIUM
- **Where:** `app.js` (global — no logging anywhere)
- **CWE:** CWE-778 (Insufficient Logging)
- **Evidence:** Zero log statements across the flow: payment transitions,
  invoice issuance, and mutations produce no actor/action/target records.
- **Impact:** The abuse stories above (spoofed webhook, cross-user invoice)
  are undetectable after the fact; investigations impossible.
- **Fix:** Structured audit events (actor, action, entity, before/after
  status) for every status write and invoice creation; alert on
  invoice-without-payment and webhook-failure spikes.

## What looks good

- `safe-flow.js` demonstrates every fix correctly: guarded transition
  (`status !== 'paid'` → 409), ownership join on both invoice handlers,
  HMAC + `timingSafeEqual` webhook verification, integer-cents money,
  post-payment freeze (`status !== 'cart'` → 409), replay guard
  (`invoices.some(orderId)`), server-derived totals.
- No SQL/eval/exec/template sinks anywhere (in-memory store) — the
  classic injection classes have no surface here.
- Secrets scan: clean — no credentials or tokens planted or leaked.
- Ownership IS checked on `/orders/:id/pay` and `PUT /orders/:id`
  (`o.userId === req.user.id`, app.js:36, :44) — the routes that look
  individually fine; the compromise is purely flow-wise.

## Recommended fix order

1. SEC-004 + SEC-001 (chain: webhook spoof → free goods) — verify webhook
   signature, gate invoice on `status === 'paid'` + completed payment (S)
2. SEC-002 + SEC-006 (chain: money theft) — server-derived totals, freeze
   order after payment (S)
3. SEC-003 + SEC-008 (chained IDOR) — ownership predicate on both invoice
   handlers (S)
4. SEC-007 replay guard (S) → then SEC-005 auth verification (M) →
   SEC-009 money representation (M) → SEC-010/SEC-011 hardening + audit
   trail (M)

Not assessed: dependency CVEs (no manifest — add a `package.json` +
lockfile), live OSV/KEV (no network). npm-audit bridge available but
unusable without a manifest.
