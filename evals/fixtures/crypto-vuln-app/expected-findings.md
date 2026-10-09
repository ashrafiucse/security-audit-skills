# crypto-vuln-app — Expected findings

Ground truth for `evals/fixtures/crypto-vuln-app` (crypto-review end-to-end).
Live OSV results informational — deps intentionally unpinned.

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | MD5 for password storage (fast unsalted hash) | app.py:15 | Critical |
| 2 | AES-ECB for card data (pattern leakage, no authentication) + hardcoded key | app.py:20 | High |
| 3 | DES encryption (56-bit key, broken) | app.py:26 | High |
| 4 | Password-reset token from non-CSPRNG (`random`, user-derived structure) | app.py:32 | High |
| 5 | TLS verification disabled (`verify=False`) | app.py:37 | High |
| 6 | PBKDF2 with 1000 iterations + static salt | app.py:42 | High |
| 7 | Multihashing with ambiguous encoding — `capability_digest` hashes `user + "|" + role + "|" + expires` (separator in a field or empty field → distinct tuples collide; attacker-influenced fields forge capability-token inputs) and `audit_digest` uses an f-string tuple hash with no domain separation — secret-prefix layout also length-extension-able (ToB SequenceHash class) | app.py:44-56 | High |

## Must NOT trigger (near-misses — `safe_app.py`)

- `hashlib.scrypt` with per-user salt (password-appropriate KDF)
- AES-GCM with random 12-byte nonce per message
- `secrets.token_urlsafe` reset token
- `verify=True` on outbound requests
- PBKDF2 600k iterations + per-user salt
- `hashlib.md5` used nowhere in the safe file (usage context is what matters)
- `safe_app.py:42-53` — `capability_digest` safe shape: domain string (`b"capability-v1"`) + length-prefixed fields (`_lenp`, 8-byte big-endian length) — no separator concatenation, tuple-unique encoding (TupleHash/SequenceHash style); zero `sha256(` calls with `+` concatenation or f-string tuple bodies anywhere in the file
