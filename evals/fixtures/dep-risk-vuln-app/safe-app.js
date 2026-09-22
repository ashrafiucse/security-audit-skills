// SAFE counter-examples for dep-risk-vuln-app. An audit must NOT report these.
const express = require('express');
const { IsolatedVM } = require('isolated-vm'); // SAFE (vs vm2): maintained isolation
const axios = require('axios');                 // SAFE (vs request): maintained client

const app = express();
app.use(express.json());

const UPDATABLE = new Set(['beta']);

app.post('/run-plugin', async (req, res) => {
  // SAFE (vs vm2): isolated-vm with explicit transfer + no require inside
  const isolate = new IsolatedVM({ memoryLimit: 32 });
  res.json({ result: String(await isolate.run('1+1')) });
});

app.post('/settings', (req, res) => {
  // SAFE (vs _.merge): allowlist-picked keys into a fresh object
  const patch = Object.fromEntries(
    Object.entries(req.body || {}).filter(([k]) => UPDATABLE.has(k))
  );
  Object.assign({}, patch);
  res.json({ ok: true });
});

app.get('/fetch-badge', async (req, res) => {
  // SAFE (vs request): maintained client, redirects OFF on user URLs
  const r = await axios.get(req.query.url, { maxRedirects: 0, timeout: 5000 });
  res.send(r.data);
});
