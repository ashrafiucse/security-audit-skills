# python-vuln-app — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Hardcoded admin token + DB password | app.py:12-13 | Critical |
| 2 | Flask DEBUG=True (Werkzeug debugger RCE) | app.py:14 | High |
| 3 | SQL injection — f-string into execute | app.py:25 | Critical |
| 4 | Plaintext password storage/comparison | app.py:26 | Critical |
| 5 | pickle.loads on request body | app.py:36 | Critical |
| 6 | yaml.load with unsafe Loader | app.py:43 | High |
| 7 | subprocess with shell=True + concatenation | app.py:50 | Critical |
| 8 | Path traversal — open(user input) | app.py:57 | High |
| 9 | Auth header + token printed to logs | app.py:62 | High |
| 10 | No rate limiting on /login | app.py:17 | Medium |
| 11 | Sequential int user IDs (enumeration on /login failures distinguishability) | app.py:24-29 | Low/Medium |
| 12 | No authentication/authorization on ANY route (census 0/6) — RCE paths reachable unauthenticated | app.py:- | Critical |
| 13 | No dependency manifest — unpinned/unverifiable stack (absence anchor: the missing file itself) | requirements.txt:- | Medium |

## Must NOT trigger

- `sqlite3.connect("app.db")` itself (local file, not injection)
- `str(cfg)`/`str(data)` (not injection sinks)
