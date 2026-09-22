# Eval Scoreboard

Round history for scored audits — the drift detector. Recall falling over
time = a pattern change broke old coverage; precision falling = noise
creeping in. Append rows automatically:

```bash
python3 scripts/score_audit.py <report.md> evals/fixtures/<fixture> \
    --append --label "what changed / PR #"
```

Manual additions (real-world benchmark rounds per `run.md`): copy the row
format. Phantoms are scorer-visible; near-miss violations (reporting a
"Must NOT trigger" item) are counted manually and go in the Trigger/Notes
column.

## Round history

| Date | Fixture/App | Recall | Precision | Phantoms | Found/Expected | Trigger |
|---|---|---|---|---|---|---|
| 2026-09-22 | node-vuln-app-2 | 90.91% | 100.00% | 0 | 10/11 | e2e baseline: subagent audit round (post v1.2.0) |
| 2026-09-22 | llm-vuln-app | 100.00% | 100.00% | 0 | 8/8 | e2e baseline: subagent audit round (post v1.2.0) |
| 2026-09-22 | iac-vuln-app | 100.00% | 100.00% | 0 | 17/17 | e2e baseline: subagent audit round (post v1.2.0) |
| 2026-09-22 | laravel-vuln-app | 100.00% | 100.00% | 0 | 11/11 | e2e frameworks round (post ground-truth fixes) |
| 2026-09-22 | django-vuln-app | 100.00% | 100.00% | 0 | 11/11 | e2e frameworks round (post ground-truth fixes) |
| 2026-09-22 | spring-vuln-app | 100.00% | 100.00% | 0 | 10/10 | e2e frameworks round (post ground-truth fixes) |
| 2026-09-22 | graphql-vuln-app | 100.00% | 100.00% | 0 | 11/11 | e2e frameworks round (post ground-truth fixes) |
| 2026-09-22 | mobile-vuln-app | 100.00% | 100.00% | 0 | 11/11 | e2e frameworks round (post ground-truth fixes) |
| 2026-09-22 | rails-vuln-app | 100.00% | 100.00% | 0 | 11/11 | e2e frameworks round — BLIND-EVAL COMPROMISED (rg scan printed 3 ground-truth lines into tool output; findings re-verified independently) |
| 2026-09-22 | flow-vuln-app | 100.00% | 100.00% | 0 | 10/10 | e2e flow-security round (new skill first run; blind hygiene honored) |
| 2026-09-22 | dep-risk-vuln-app | 100.00% | 100.00% | 0 | 8/8 | e2e dep-risk round (beyond-CVEs pack first run; blind hygiene honored) |
