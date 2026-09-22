# Maintenance — Keeping the Skills Current

Security knowledge decays. This document is the operating manual for keeping the
repo effective as new vulnerabilities become public, and for making it
*smarter* over time. Consumers update with `git pull`; releases are tagged.

## 1. Inputs (subscribe to all)

| Source | What it gives | URL |
|---|---|---|
| CISA KEV | Actively exploited CVEs, with fix due dates | cisa.gov/known-exploited-vulnerabilities-catalog (JSON feed automated below) |
| OSV.dev | Aggregated CVE/GHSA/PYSA/RUSTSEC/Go advisories — powers the dependency skill live | osv.dev |
| GitHub Security Advisories | Ecosystem advisories + affected-version ranges | github.com/advisories |
| NVD 2.0 API | Canonical CVE data, CVSS | nvd.nist.gov/developers/vulnerabilities |
| Project Zero / PortSwigger research | New *classes* of bugs → new detection patterns | googleprojectzero.blogspot.com, portswigger.net/daily-swig |
| Snyk/Palo Alto unit42 blogs | Exploitation trends, patterns worth grepping for | — |

## 2. Cadence

### Daily (automated, ~zero human time until an issue lands)
- **06:00 UTC** — `update-kev.yml`: opens a triage issue only for new exploited CVEs not already covered (dedupes against vuln-db entries and open issues). Daily cron, stateless, never commits.
- **06:15 UTC** — `critical-cve-digest.yml`: opens one digest issue with copy-paste-ready entry drafts for new CRITICAL CVEs (NVD, last 3 days).
- `notify.yml`: when any actionable issue (triage/miss/vuln-db) opens, comments with @ashrafiucse (→ GitHub notification) and optionally pings Slack via the `SLACK_WEBHOOK_URL` secret.
- Community inputs: `missed-finding` and `vuln-db` issue templates turn user reports into structured triage work.
- CI (`.github/workflows/ci.yml`) runs validation and self-tests on every push/PR — keep it green.

Automation inventory:

| Workflow | Cadence | Output | Human action |
|---|---|---|---|
| `update-kev.yml` | daily 06:00 UTC | deduped KEV triage issue | vuln-db entries for ecosystem items; close infra-only |
| `critical-cve-digest.yml` | daily 06:15 UTC | digest issue with drafts | pick items with in-repo detection |
| `notify.yml` | on issue opened | @maintainer mention (+optional Slack) | none |
| `ci.yml` | push / PR | quality gate | keep green |

Triage target: ecosystem-relevant KEV entries within 7 days (CISA due dates are short).
Ensure your watch is "All Activity" (repo page → Watch), so bot-opened issues always notify.

**Branch protection:** `main` is protected by the `protect-main` ruleset — direct
pushes, force pushes, and deletion are all blocked; every change lands via a PR
gated on the required CI check (`test`). Emergency override: temporarily set
the ruleset to *disabled* (Settings → Rules → Rulesets), do the change, restore it.

### Monthly (~2 h) — pattern refresh
- Review the month's high-profile advisories for *new bug classes or APIs* (not just CVEs). New dangerous API → new grep pattern in the relevant skill's `references/`, + fixture.
- Re-run evals on all fixtures; fix any precision regressions (new patterns causing false positives are the #1 decay mode).
- **Adversarial drill (30 min, one skill per month, rotate):** try to write code that *defeats* the skill — a real bug phrased so its greps miss it, and a safe near-miss phrased so its greps fire. Whatever you find becomes a fixture + pattern. Attack your own patterns like a red team; fixture sets that only contain bugs phrased the way the author already thought of them don't generalize.
- Scan `evals/SCOREBOARD.md` for drift: any fixture/skill whose recall or precision dropped vs. its last row gets a bisect (`git log --oneline skills/<skill>`) and a regression row in `MISSES.md`.

### Quarterly (~half day) — external benchmark
- Run `/skill:security-audit` against the real-world test beds (Juice Shop, Node Goof, Railsgoat, WebGoat — see `evals/README.md`).
- Score recall/precision; convert misses into fixtures + patterns.
- Sweep dependency knowledge: deprecated packages list, new manifest formats (e.g. a new lockfile format) → update `osv_scan.py` parsers.

## 3. The improvement loop (how the skills "learn")

```
user reports a miss or a FALSE POSITIVE (issue templates)
   → maintainer LOGS it in evals/MISSES.md the same session (open row — no miss untracked)
   → maintainer writes a fixture reproducing it (evals/) — planted finding for a miss,
     a near-miss for a false positive
   → adds/updates detection guidance (references/ or vuln-db/) — widen for recall,
     narrow for precision
   → re-runs eval round (all fixtures must still pass; SCOREBOARD row appended)
   → PR merged → version tag → MISSES.md row closed
```

Two decay modes to guard against:
1. **False positives creep** — every new pattern slightly noisier. Eval precision ≥ 80% is the gate.
2. **Stale knowledge** — entries older than 18 months with no detection signal get pruned; the live OSV/KEV lookups are the always-fresh layer, the vuln-db is the *curation* layer.

## 4. Versioning & releases

- SemVer: MAJOR = removed/renamed skills or breaking SKILL.md contract changes; MINOR = new skill/patterns/entries; PATCH = fixes to existing patterns.
- Tag releases (`v1.4.0`) so consumers can pin; README states the "consume via git pull" model.
- Changelog lives in release notes (generated from PR titles).

## 5. Cost model

**Money: $0.** Public repo → Actions minutes free (~20 min/month used); OSV.dev,
CISA KEV, and NVD APIs are free at this volume (digest = 1 NVD request/day);
no backend — skills run on each consumer's agent.

**Time (solo steady state): ~1–2 h/week** — triage sessions 2–3×/week (issue →
entry ≈ 15–20 min each; most digest items are 1-minute closes), ~2 h monthly
pattern refresh, ½ day quarterly benchmark. Community miss-reports add
20–30 min per accepted fix but scale to contributors via the issue templates.

**Safe to pause:** the live OSV/KEV layer is the primary freshness mechanism and
needs no maintenance; vuln-db curation improves quality, not correctness — a
pause just accumulates open issues, nothing breaks.

Noise knobs if it ever feels heavy: digest cron frequency, severity bar
(CRITICAL → +HIGH), keyword filter in `critical-cve-digest.yml`.

Free GitHub protections on this repo (all $0 on public repos): secret scanning
+ push protection (verified active), Discussions (community Q&A lives there
so Issues stay triage-only), and private vulnerability reporting (verified
enabled — reporters use Security → "Report a vulnerability").

**Dependabot intentionally disabled**: the only dependency manifests in this
repo are intentional eval fixtures (`evals/fixtures/`) — Dependabot flagged
69 "vulnerabilities" there, all by design. The repo's real supply chain is
stdlib-only (zero runtime dependencies), so the actual exposure is nil.

## 6. Published

Live at: https://github.com/ashrafiucse/security-audit-skills

Fresh-clone setup:

```bash
git remote add origin https://github.com/ashrafiucse/security-audit-skills.git
```

Housekeeping (owner):

```bash
gh repo edit ashrafiucse/security-audit-skills \
  --description "Agent skills that security-audit any codebase" \
  --add-topic security --add-topic agent-skills --add-topic code-security
```

Once after publishing: run the KEV workflow manually (Actions → Weekly CISA KEV
triage → Run workflow) to confirm it opens triage issues, and check CI is green.
The workflow is stateless — it only opens issues and never commits. Keep it that
way (least privilege, and no bot entries in the contributor graph).
