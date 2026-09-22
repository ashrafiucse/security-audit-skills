# THREAT-MODEL — CourseForge (design stage)

Produced by design-threat-review from `spec.md` (v0.3). This is the audit
contract: security-audit Phase 0 loads the coverage matrix below; every threat
section must be dispositioned at audit time.

## 1. Actor × asset power matrix

| Actor ↓ / Asset → | Course content (paid) | Student PII | Money/entitlement | Admin power |
|---|---|---|---|---|
| Anonymous | none (preview only) | none | none | none |
| Student | read (enrolled) | own | pay→enroll | none |
| Instructor | own courses | cohort PII | none | course-scoped |
| Admin | all | all | grant/refund | full |
| PayGate webhook (service) | none | none | **marks paid + enrolls** | none |

## 2. Flows & trust boundaries

1. Catalog read (browser↔app↔db)
2. Preview (browser↔app↔db) — paid content
3. Review: student submits → stored → pending queue → **staff opens detail (admin origin)** → approve → public page
4. PayGate → webhook (external↔app) → order paid → enrollment
5. Materials fetch (support staff ↔ app ↔ db, cohort-scoped intent)
6. Support: student display name → admin panel reply view

## 3. Threats

### T-01: Catalog exposes draft/private courses — High
- **Actor → Asset:** anonymous → course content (pre-launch IP)
- **Surface:** public catalog list
- **Spec anchor:** spec.md:7-8
- **Detector skill:** ../course-platform-security/SKILL.md §2
- **Acceptance criterion:** every public read path (list, detail, counts, facets, sitemap) filters status=published AND visibility=public

### T-02: Preview returns full lesson array, client-side gating only — Critical
- **Actor → Asset:** anonymous → paid content
- **Surface:** preview endpoint
- **Spec anchor:** spec.md:11-13
- **Detector skill:** ../course-platform-security/SKILL.md §3
- **Acceptance criterion:** preview response is server-side limited to N items by field selection — never the full content array

### T-03: Review body stored as submitted, staff detail renders with line breaks preserved, no escape specified — Critical
- **Actor → Asset:** student → admin power
- **Surface:** moderation detail view (admin origin); the pending queue guarantees a privileged viewer opens it
- **Spec anchor:** spec.md:17-19
- **Detector skill:** ../laravel-security/SKILL.md Step 4 (privilege direction) + ../course-platform-security/SKILL.md §6.5
- **Acceptance criterion:** review body passes an escaper before ANY formatting in EVERY staff view (list AND detail) or is purified at write

### T-04: Webhook accepts any payload shape, marks paid + enrolls — Critical
- **Actor → Asset:** PayGate spoofer → entitlement
- **Surface:** payment webhook
- **Spec anchor:** spec.md:24-26
- **Detector skill:** ../flow-security/SKILL.md (F8) + ../auth-review/SKILL.md
- **Acceptance criterion:** signature verified before any state write; replayed event ids rejected

### T-05: Materials API takes courseId AND cohortId as parameters — Critical
- **Actor → Asset:** any requester → cohort content
- **Surface:** lesson-materials API
- **Spec anchor:** spec.md:29-31
- **Detector skill:** ../auth-review/SKILL.md (tenant-scope census) + ../course-platform-security/SKILL.md §5
- **Acceptance criterion:** reads scoped by the caller's membership record; staff use a separate role-guarded endpoint

### T-06: Display names free-text, read by support agents in admin panel — Critical
- **Actor → Asset:** student → admin power
- **Surface:** support/admin panel reply view
- **Spec anchor:** spec.md:34-35
- **Detector skill:** ../injection-flaws/SKILL.md + ../course-platform-security/SKILL.md §6.5
- **Acceptance criterion:** display names escaped at every staff render

## 4. Abuse cases (attacker personas)

- Cheater student: preview for full content (T-02); self-enroll via forged webhook (T-04)
- Cohort-hopper: materials API with another cohortId (T-05)
- Session thief: review/display-name payload that fires when staff opens it (T-03/T06) — the approval workflow itself is the delivery mechanism
- Competitor: draft catalog scrape (T-01)

## 5. Pre-seeded actor × surface coverage matrix (all cells ⬜ — audit disposition-checks)

| Surface ↓ / Actor → | anonymous | student | staff/mod | admin | webhook svc |
|---|---|---|---|---|---|
| Catalog | ⬜ | ⬜ | n/a | n/a | n/a |
| Preview | ⬜ | ⬜ | n/a | n/a | n/a |
| Review write | n/a | ⬜ | n/a | n/a | n/a |
| Moderation detail | n/a | n/a | ⬜ | ⬜ | n/a |
| Webhook/enrollment | n/a | ⬜ | n/a | ⬜ | ⬜ |
| Materials | ⬜ | ⬜ | ⬜ | n/a | n/a |
| Support panel | n/a | ⬜ | ⬜ | n/a | n/a |

## Handoff
Acceptance criteria above are implementation security requirements. The first
audit runs the detector skills and must disposition every threat section and
every matrix cell; any ⬜ left is an incomplete audit.
