# MISSES — the miss ledger

Every finding the skills failed to catch, logged the same session it was
discovered — then converted into a pattern + fixture (see MAINTENANCE.md §3).
This file is the memory that makes the same miss impossible twice. Rows are
never deleted; closed rows stay as history.

## Open misses

(none)

## Closed misses

| Date | Source | What was missed | Skill | Pattern added | Fixture |
|---|---|---|---|---|---|
| 2026-09-22 | coverage audit | 9 uncovered classes: prototype pollution, NoSQL operator injection, XXE, ReDoS, open redirect, trusted-header authz, TOCTOU races, WebSocket/SSE authz, generic file-upload abuse | injection-flaws, auth-review | sections in both SKILL.md + patterns.md | node-vuln-app-2, python-vuln-app-2 |
| 2026-09-22 | coverage audit | route census (unguarded endpoints found only by pattern luck), second-order/stored flows, query-builder raw sinks, multi-line query construction | auth-review, injection-flaws | census table in auth-review §1; second-order + builder + multiline sections | node-vuln-app-3 |

## How to add a row

1. When a user reports a miss (issue) or a quarterly benchmark (Juice Shop
   etc.) finds one, open a row **the same session** — status open.
2. Write the fixture reproducing it (`evals/fixtures/…` + expected findings).
3. Add the detection guidance to the skill.
4. Re-run `python3 scripts/selftest_patterns.py` + `python3 scripts/validate.py`.
5. Move the row to Closed with pattern + fixture links.
