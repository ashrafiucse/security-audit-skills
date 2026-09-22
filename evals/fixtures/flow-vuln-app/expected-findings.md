# flow-vuln-app — Expected findings

Ground truth for `evals/fixtures/flow-vuln-app` (cross-endpoint business-flow
vulnerabilities — see `flow-security` skill, classes F1–F8). Every endpoint is
individually defensible (auth present, ownership on direct fetch, no SQLi) —
the findings ONLY exist across the order → payment → invoice flow.

| # | Class | Finding | Where | Severity |
|---|---|---|---|---|
| 1 | F1/F5 | Unguarded transition + step-skip — invoice creation has no `status==='paid'` precondition and no payment-existence check: invoice a `cart` order, or an order with no payment at all | app.js:62-77 | Critical |
| 2 | F2 | Client-supplied money at the terminal step — invoice total from `req.body.total`, not the persisted order row | app.js:69 | Critical |
| 3 | F3 | Association IDOR (create) — `POST /invoices` fetches the order without `order.userId === caller`: any user invoices any order | app.js:65 | Critical |
| 4 | F3 | Association IDOR (read) — `GET /invoices?order_id=` filters without joining to `order.userId`: cross-user invoice read | app.js:80-83 | High |
| 5 | F4 | Replay/duplication — no uniqueness on `orderId`/payment in invoices; webhook retry or re-POST duplicates invoices | app.js:76 | High |
| 6 | F6 | Post-boundary mutation — `PUT /orders/:id` has no status guard; order editable (items/total) after payment | app.js:35-41 | High |
| 7 | F7 | Amount drift — float arithmetic (`sum + i.price * i.qty`) for money at the boundary step | app.js:28-29 | Medium |
| 8 | F8 | Spoofable flow hop — payment webhook has no signature/HMAC verification; the `paid` transition rests on an unauthenticated callback | app.js:52-60 | Critical |
| 9 | Authn | Identity taken verbatim from the Authorization header (`req.user = {id: header.slice(7)}`) — no token verification (trusted-header class) | app.js:18-19 | Critical |
| 10 | Hardening | No security headers / no rate limiting on payment+invoice endpoints (file-level anchor) | app.js:- | Medium |

## The flow abuse stories (any one proves the class)

- Invoice-before-payment: `POST /invoices {order_id: o1}` on a fresh cart order → 201
- Price tamper: order → pay → `PUT /orders/o1 {total: 0.01}` → invoice reads… (with F2 even simpler: send `total` in the invoice POST body)
- Cross-user: bob POSTs `/invoices {order_id: aliceOrder}` → invoice issued to bob for alice's order; bob reads all invoices via `?order_id=`
- Replay: re-send webhook / re-POST invoice → duplicates
- Spoof: `POST /payments/webhook {payment_id: p1}` as anyone → order transitions to paid without any payment

## Must NOT trigger (near-misses — `safe-flow.js`)

- `status !== 'cart'` → 409 mutation guard (F6 safe form)
- HMAC + timing-safe webhook verification (F8 safe form)
- Invoice precondition: ownership join + `status==='paid'` + already-invoiced guard + total from order row (F1/2/3/5 safe forms)
- Integer minor-units money helper (F7 safe form)
- `requireAuth` on both invoice endpoints (present in BOTH files — auth alone is not the finding here)
