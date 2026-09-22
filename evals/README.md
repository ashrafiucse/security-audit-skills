# Evals — How We Measure Skill Quality

Skills aren't trained; they're **tested**. This directory is the regression suite:
vulnerable code fixtures with expected findings. Every detection rule change runs
against it. Quality = precision (no false positives) + recall (finds what's planted).

## Layout

```
evals/
├── fixtures/<scenario>/     # intentionally vulnerable projects (SAFE to scan)
│   ├── expected-findings.md # ground truth per scenario
└── run.md                   # how to run an eval round
```

## Running a round

1. Open an agent session with this repo's skills loaded
2. Run the audit against a fixture:
   ```
   /skill:security-audit /path/to/security-skills/evals/fixtures/node-vuln-app
   ```
3. Compare `SECURITY-AUDIT.md` against the fixture's `expected-findings.md`
4. Record results:

| Metric | Meaning | Target |
|---|---|---|
| Recall | planted findings reported / total planted | ≥ 90% |
| Precision | real findings / total reported | ≥ 80% |
| Phantom | findings that reference nonexistent evidence | 0 |

## Rules

- **Every accepted PR that adds/changes a detection pattern must add or update a fixture.** No fixture, no merge.
- **Every miss goes in `MISSES.md`** (this directory) the session it's found — open row until the pattern + fixture land. A miss without a ledger row didn't happen.
- **Every false positive gets the same treatment** — `[fp]` issue → narrowed pattern + near-miss fixture. Recall and precision train symmetrically; drift history lives in `SCOREBOARD.md`.
- Fixtures contain ONLY fake data: `AKIAIOSFODNN7EXAMPLE`-style keys, `example.com` hosts, `password123` values. Never real secrets — people will clone this repo.
- A finding that a fixture *shouldn't* trigger (near-miss) is as valuable as a planted one — add both.
- Fixtures also serve as living examples of what each finding looks like.

## Scaling up: real-world test beds

Run full audits against well-known intentionally-vulnerable apps quarterly
(clone locally, never attack hosted instances):

- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — Node/Express, full OWASP Top 10
- [Node Goof](https://github.com/snyk-labs/node-goof) — vulnerable npm deps (good for `dependency-vulns`)
- [Railsgoat](https://github.com/OWASP/railsgoat) — Ruby on Rails
- [WebGoat](https://github.com/WebGoat/WebGoat) — Java/Spring
- [DVNA](https://github.com/appsecco/dvna) — Node

Score the same way. Track regressions per skill in the PR description.
