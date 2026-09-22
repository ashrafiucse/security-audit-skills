# c-vuln-app — Expected findings

Ground truth for `evals/fixtures/c-vuln-app` (C/C++ native security pack —
see `injection-flaws/references/patterns.md` "C/C++ native code").

| # | Class | Finding | Where | Severity |
|---|---|---|---|---|
| 1 | Format string | `fprintf(stderr, user_agent)` — user data as the FORMAT argument (`%n` write primitive), argv-reachable | service.c:8 | High |
| 2 | Buffer overflow | fixed 32-byte `name` filled from unbounded input path | service.c:13-14 | High |
| 3 | Unbounded copy | `strcpy(name, input)` — no bound check | service.c:15 | High |
| 4 | Command injection | `system()` with format-built command incl. user value | service.c:25 | Critical |
| 5 | Integer overflow → heap overflow | `malloc(len + 1)` with `unsigned int` wraps at `UINT_MAX` → tiny alloc, huge `memcpy` | service.c:31-34 | High |

## Must NOT trigger (near-misses — `safe_service.c`)

- `fprintf(stderr, "%s", user_agent)` — literal format
- Bounded `memcpy` after explicit `strlen` guard matching the destination size
- Allowlisted `execvp` without shell
- `size_t` + explicit overflow guard before alloc
