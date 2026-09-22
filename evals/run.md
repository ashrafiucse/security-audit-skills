# Running an eval round

An eval round measures skill quality: can an agent audit, using these skills,
find everything planted in a fixture — without inventing findings?

## 1. Pick the fixture

Any directory under `fixtures/`. Each contains an intentionally vulnerable
mini-project (FAKE data only) and `expected-findings.md` ground truth:
planted findings + near-misses that must NOT trigger.

## 2. Run the audit

Start an agent session with this repo's skills loaded (see README install),
then:

```
/skill:security-audit <repo>/evals/fixtures/<scenario>
```

Have it write the report to a scratch path so you can score it before it
overwrites anything, e.g. ask for `SECURITY-AUDIT.md` in the fixture dir
(fixtures are read-only inputs — reset with `git checkout` after the round).

## 3. Score it

```
python3 scripts/score_audit.py <path-to>/SECURITY-AUDIT.md evals/fixtures/<scenario> \
    --min-recall 0.90 --min-precision 0.80 --max-phantoms 0
```

The scorer matches report citations (`file:line`) against ground truth rows
(±2 line tolerance). Manual pass afterwards for what it can't judge:

- **Near-miss violations**: any "Must NOT trigger" item reported → precision
  miss (count it manually; the scorer can't read judgment).
- **Category correctness**: right CWE/severity framing, not just right line.
- **Quality**: does the fix recommendation actually fix it?

## 4. Record the round

- Append to the drift history automatically:
  ```
  python3 scripts/score_audit.py <report> evals/fixtures/<scenario> \
      --append --label "<what changed / PR #>"
  ```
  (`evals/SCOREBOARD.md`; real-world benchmarks get manual rows in the same format.)
- Every miss → open row in `MISSES.md` the same session; every near-miss
  violation (reporting a "Must NOT trigger" item) → false-positive issue
  template + pattern narrowing.
- Regressions block merge: re-run ALL fixtures if you changed shared skills
  (`injection-flaws`, `auth-review`) — `python3 scripts/selftest_patterns.py`
  catches the grep-level half automatically.

## Targets

| Metric | Target |
|---|---|
| Recall | ≥ 90% per fixture |
| Precision | ≥ 80% per fixture |
| Phantom findings | 0 |
| Near-miss violations | 0 |
