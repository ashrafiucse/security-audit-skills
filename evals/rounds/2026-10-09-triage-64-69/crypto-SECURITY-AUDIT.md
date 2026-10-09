# Security Audit — crypto-vuln-app (research conversion round, issue #65)
Date: 2026-10-09 | Scope: working tree (fixture) | Auditor: security-skills dev (IN-PROCESS run — ground-truth-aware artifact validation, not blind recall; see scoreboard label)
Trigger: ToB "SequenceHash: multihashing for the rest of us" (blind-predict protocol, issue #65) — ambiguous-encoding multihashing class converted to crypto-review §3 (concat + f-string tuple hashes, length-extension, domain separation). New row 7 + length-prefixed safe counterpart.

## Stack
Python app (app.py): password hashing, card encryption, reset tokens, webhook fetch, KDF, capability/audit digests. Safe counterpart (safe_app.py). requirements.txt intentionally unpinned (live OSV informational).

## Summary
| Severity | Count |
|---|---|
| Critical | 1 |
| High | 6 |

## Findings
### SEC-01: MD5 for password storage — CRITICAL
- **Where:** `app.py:15` — **CWE-327** — fast unsalted hash; bcrypt/argon2id required.

### SEC-02: AES-ECB for card data + hardcoded key — HIGH
- **Where:** `app.py:20` — **CWE-327/798** — pattern leakage, no authentication, literal key.

### SEC-03: DES encryption (56-bit) — HIGH
- **Where:** `app.py:26` — **CWE-327** — broken cipher.

### SEC-04: Password-reset token from non-CSPRNG — HIGH
- **Where:** `app.py:32` — **CWE-338** — `random.randint`, user-derived structure.

### SEC-05: TLS verification disabled — HIGH
- **Where:** `app.py:37` — **CWE-295** — `verify=False`.

### SEC-06: PBKDF2 with 1000 iterations + static salt — HIGH
- **Where:** `app.py:42` — **CWE-916** — trivial work factor, shared salt.

### SEC-07: Multihashing with ambiguous encoding — HIGH
- **Where:** `app.py:44-56` — **CWE-347/310** — `capability_digest` hashes `user + "|" + role + "|" + expires` (separator inside a field or empty field → distinct logical tuples collide; attacker-influenced fields forge capability-token inputs) and `audit_digest` uses `hashlib.sha256(f"{action}:{target}")` with no domain separation; secret-prefix layout is also length-extension-able with SHA-2 (ToB SequenceHash class, 2026-10). Safe shape: length-prefixed fields + domain/customization string (TupleHash/SequenceHash style), HMAC/SequenceMAC for keyed use.
