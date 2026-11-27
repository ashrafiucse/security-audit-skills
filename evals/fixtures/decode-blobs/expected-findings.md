# decode-blobs — Expected findings

Ground truth for `evals/fixtures/decode-blobs` (crypto-review §3.5 blob-triage
flow; decoder: `skills/crypto-review/scripts/decode_blob.py`). All values are
FAKE. Deterministic offline decoding — no network items in ground truth.

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Encoded credential — base64→zlib layers hide `db_password` for svc_audit (decode_blob peels both layers) | blobs.txt:7 | High |
| 2 | Double-hex encoded API token (`api_token=AKIA…` revealed after two hex peels) — encoding used as obfuscation | blobs.txt:10 | Medium |
| 3 | URL-encoded credential pair (`admin:P@ssw0rd-UrlEnc`) in config blob list | blobs.txt:13 | High |
| 4 | JWT with `role:"admin"` claim decoded from token; signature is a placeholder never verified — treat claims as attacker-influenceable until verification exists | blobs.txt:16 | High |
| 5 | Homemade obfuscation — single-byte XOR (0x42) session token, base64-wrapped (crypto-review §2 "custom obfuscation = rate as broken") | blobs.txt:19 | High |
| 6 | Classical-cipher (ROT13) hidden vault passphrase (`Hunter2Blue`) — obfuscation, not protection | blobs.txt:25 | Medium |
| 7 | CRITICAL CHAIN — OpenSSL `Salted__` ciphertext (blobs.txt:28) + hardcoded `CRYPTO_KEY` in app-config.env:4: ciphertext+key in one repo = decryptable credential storage; report BOTH file:line and the §3.5 chain rule | blobs.txt:28, app-config.env:4 | Critical |

## Must NOT trigger (near-misses)

- `plain-notes.txt:4` — plain-English meeting-notes prose: NOT encoded, the decoder must stop ("plain text"), reporting it as a "decoded blob" is a false positive.
- A bcrypt/argon2-shaped hash (none planted by design here — they live in crypto-vuln-app): one-way formats are identified, never reported as "decoded". If the auditor "decodes" any hash-shaped value, that is a precision miss.

## Informational (out of ground truth)

- Live verification of the JWT signature, or actual decryption of the Salted__ envelope with the planted key, is a CONFIRM step (offline-safe to skip in scoring).
