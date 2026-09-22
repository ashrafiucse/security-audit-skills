# design-threat-review-vuln-app — Expected findings

Ground truth for `evals/fixtures/design-threat-review-vuln-app` (design-threat-review
skill — spec in, THREAT-MODEL.md out). Judgment-based fixture: no grep self-test
rules (design reading, not sink matching) — per LEARNINGS, judgment findings live
in ground truth only.

| # | STRIDE | Threat (severity-if-missed) | Where | Severity |
|---|---|---|---|---|
| 1 | Info disclosure | Catalog lists EVERY course incl. unpublished/private drafts on the public list — no status/visibility filter specified | spec.md:7-8 | High |
| 2 | Info disclosure | Preview endpoint returns the FULL lesson array; free/paid gating is client-side only — paid content free | spec.md:11-13 | Critical |
| 3 | Tampering + Elevation | Review body "stored as submitted", staff detail view renders with "line breaks preserved" — no escape/purification anywhere: unprivileged→privileged render → staff-origin XSS → admin ATO (the approval flow guarantees a privileged viewer opens it) | spec.md:17-19 | Critical |
| 4 | Spoofing + Repudiation | PayGate webhook "accepts any payload shape" — no signature verification, no replay protection, writes paid+enrolls | spec.md:24-26 | Critical |
| 5 | Info disclosure / Elevation | Materials API takes `courseId` AND `cohortId` as parameters — no membership scoping: cross-cohort + non-student read | spec.md:29-31 | Critical |
| 6 | Tampering + Elevation | Display names free-text at signup, read by support agents in the admin panel — unprivileged→privileged render again | spec.md:34-35 | Critical |

## Must NOT trigger (near-misses — `safe-spec.md`)

- Catalog filtered `published AND public` on every public read path (§1) — control specified
- Preview server-side limited to N lessons by field selection (§2)
- Review body escaped (`e()`) before line-break formatting in EVERY staff view (§3)
- Webhook signature verification + replay rejection before state write (§4)
- Materials scoped by the caller's enrollment record; staff use a separate role-guarded endpoint (§5)
- Display names escaped everywhere (§6)

## Notes

- The expected deliverable is a THREAT-MODEL.md whose threat rows cover #1–#6
  (actor/asset/surface/severity/detector-skill/acceptance-criterion) and whose
  actor×surface matrix pre-seeds the future security-audit. A threat row with
  no detector skill AND no acceptance criterion is itself a gap.
