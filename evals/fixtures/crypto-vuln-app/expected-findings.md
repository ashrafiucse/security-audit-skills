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

## Must NOT trigger (near-misses — `safe_app.py`)

- `hashlib.scrypt` with per-user salt (password-appropriate KDF)
- AES-GCM with random 12-byte nonce per message
- `secrets.token_urlsafe` reset token
- `verify=True` on outbound requests
- PBKDF2 600k iterations + per-user salt
- `hashlib.md5` used nowhere in the safe file (usage context is what matters)
