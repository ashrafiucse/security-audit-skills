# PHANTOMS — the false-positive ledger

Mirror of `MISSES.md` for **precision**: every confirmed false positive is
logged the session it was confirmed, then converted — narrowed pattern +
near-miss fixture row + MUST_NOT_MATCH guard where the narrowing is
mechanical. Rows are never deleted; converted rows stay as history.

**Probation rule:** three open (unconverted) rows against one pattern means
that pattern is on probation — rewrite it or retire it; do not keep
patching triage prose.

Report one: the **[fp] issue template** (`.github/ISSUE_TEMPLATE/false-positive.yml`).

## Open false positives

- none yet

## Converted false positives

| Date | Source | What fired wrongly | Skill | Narrowing added | Fixture/guard |
|---|---|---|---|---|---|
| 2026-09-25 | adversarial drill (gaps4) | `innerHTML` grep had no documented fires-but-safe forms — DOMPurify-sanitized, clearing (`= ''`), and code-owned-constant hits all looked like findings to an auditor without a falsifier | injection-flaws | falsifier line requirement (report contract) + triage counter-example file | gaps4-vuln-app/triage-gaps4.js + selftest match rule pinning the DOMPurify line |
