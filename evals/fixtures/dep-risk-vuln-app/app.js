// Fixture: package-level risk with clean-looking main code. FAKE data only.
// The app logic itself is defensible — the risk is IN the packages and how
// they're used. Safe forms in safe-app.js.
// Expected findings: see expected-findings.md
const express = require('express');
const _ = require('lodash');
const { VM } = require('vm2');
const request = require('request');

const app = express();
app.use(express.json());

const config = { featureFlags: { beta: false } };

// SEC-01: vm2 — discontinued, unpatched sandbox escapes; ANY version.
// Running user code in it is code execution with a broken fence.
app.post('/run-plugin', (req, res) => {
  const vm = new VM({ timeout: 1000, sandbox: {} });
  res.json({ result: String(vm.run(req.body.script)) });
});

// SEC-02: dangerous usage of a SAFE package — lodash.merge with
// user-controlled keys (prototype pollution; version is irrelevant)
app.post('/settings', (req, res) => {
  _.merge(config, req.body);
  res.json({ ok: true });
});

// SEC-03: request — deprecated/unmaintained; SSRF via redirect never fixed
app.get('/fetch-badge', (req, res) => {
  request({ url: req.query.url, followAllRedirects: true }, (err, r, body) => {
    res.send(body);
  });
});
