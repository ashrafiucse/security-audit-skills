// Fixture: intentionally vulnerable Node/Express app. FAKE data only.
// Expected findings: see expected-findings.md
const express = require('express');
const mysql = require('mysql2');
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();

const DB_PASSWORD = 'Sup3rS3cretPr0dPass!';
const AWS_ACCESS_KEY_ID = 'AKIAI44QH8DHBEXAMPLE';

const connection = mysql.createConnection({
  host: 'db.internal.example.com',
  user: 'app',
  password: DB_PASSWORD,
  database: 'shop',
});

app.get('/users', (req, res) => {
  // SEC-01: SQL injection
  connection.query(
    `SELECT * FROM users WHERE name = '${req.query.name}'`,
    (err, results) => res.json(results)
  );
});

app.get('/ping-host', (req, res) => {
  // SEC-02: OS command injection
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => res.send(stdout));
});

app.get('/greet', (req, res) => {
  // SEC-03: reflected XSS
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});

app.post('/hash', (req, res) => {
  // SEC-04: weak hash for password-like data + static IV
  const key = crypto.createHash('md5').update(req.body.password).digest('hex');
  const iv = Buffer.from('1234567890123456');
  const cipher = crypto.createCipheriv('aes-256-cbc', req.app.locals.key, iv);
  res.json({ key });
});

app.get('/fetch-url', async (req, res) => {
  // SEC-05: SSRF
  const r = await fetch(req.query.url);
  res.json(await r.json());
});

app.get('/admin/users', (req, res) => {
  // SEC-06: IDOR / missing auth
  connection.query(
    `SELECT * FROM users WHERE id = ${req.params.id}`,
    (err, results) => res.json(results[0])
  );
});

app.listen(3000, () => console.log('started with key', AWS_ACCESS_KEY_ID));
