// Fixture: server-side hardening gaps. FAKE data only.
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  // SEC-06: auth cookie without __Host-/__Secure- prefix (no subdomain pinning)
  res.cookie('session', 'tok123', { httpOnly: true, secure: true });
  // SEC-07: CRLF injection — user data into the Location header
  res.setHeader('Location', '/welcome?name=' + req.query.name);
  res.end();
});

// SEC-08: unbounded list endpoint (API4)
app.get('/items', async (req, res) => {
  res.json(await db.items.find({})); // no limit/page
});

app.listen(3000);
