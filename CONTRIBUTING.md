# Contributing

Thanks for helping make every project that uses these skills safer.

## Repo map

```
skills/<skill-name>/SKILL.md          # the skill (frontmatter + workflow)
skills/<skill-name>/references/*.md   # deep pattern libraries (loaded on demand)
skills/<skill-name>/scripts/*         # helper scanners (portable: bash/python3 stdlib only)
skills/cve-research/vuln-db/          # versioned vulnerability knowledge base
evals/fixtures/<scenario>/            # vulnerable test projects + expected findings
scripts/validate.py                   # lint: frontmatter, cross-refs, vuln-db entries
.github/workflows/ci.yml              # validation + self-tests on every PR
.github/workflows/update-kev.yml      # weekly automated KEV monitoring
```

## Ground rules

1. **Skills are read-only scanners.** No PR may add code that modifies the audited project (beyond writing `SECURITY-AUDIT.md`), deletes anything, or performs real exploitation.
2. **Portable only.** Scripts may depend on bash, grep, and Python 3 stdlib — nothing else. Skills' prose may assume `rg` or `grep` with documented fallbacks.
3. **Precision first.** A pattern that fires on every third line gets ignored by humans, which is worse than not having it.
4. **Every behavior change ships with a fixture.** New pattern → new (or updated) fixture in `evals/fixtures/` with an `expected-findings.md` entry, including a near-miss that must NOT trigger.
5. **No real secrets — and no push-protection trips.** GitHub's secret-scanning push protection blocks any push whose *history* contains realistic provider tokens. Use documented example keys (`AKIAIOSFODNN7EXAMPLE`), publishable-key formats, connection strings with fake passwords (`postgres://app:Fake4EvalsDoNotUse@...`), or off-format fakes (`hf_FakeTokenForEvalFixtures123`). If a push is rejected: rewrite the history (see MAINTENANCE.md), never allowlist. Run `skills/secrets-detection/scripts/scan.sh` on your fixture before committing — it should find the planted fakes and nothing real.

## Adding a vulnerability entry (vuln-db)

1. Check `skills/cve-research/vuln-db/entries/` for an existing entry for the CVE — update rather than duplicate.
2. Copy `entry-template.md`, fill every section. **Detection must be agent-executable** (greps, version checks) from the target repo alone.
3. If the entry introduces a new grep pattern, add it to the relevant skill's `references/` + fixture.

## PR checklist

- [ ] Fixtures added/updated and passing (audit run reports planted findings, no phantoms)
- [ ] `python3 scripts/validate.py` passes (frontmatter, cross-references, vuln-db entries)
- [ ] `python3 scripts/selftest_patterns.py` passes (greps still match planted lines; safe files stay clean)
- [ ] New/changed skills scored with `python3 scripts/score_audit.py` per `evals/run.md` where a fixture exists
- [ ] `bash -n` clean for shell scripts; `python3 -m py_compile` clean for python
- [ ] SKILL.md frontmatter valid (`name` lowercase-hyphens, description specific, ≤1024 chars)
- [ ] No real secrets, credentials, or live URLs that imply them
- [ ] Docs updated (README skill table if adding a skill; pattern tables in `references/`)

## Reporting a missed finding (users)

Open an issue with: the code snippet (sanitized), what the vulnerability was, which skill should have caught it. Maintainers convert it into a fixture + pattern — that's how the skills get smarter (see MAINTENANCE.md).
