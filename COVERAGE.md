# Coverage Map & Roadmap

Honest assessment of where the skills are strong and thin. Contributors: pick
anything from "Help wanted" — each item maps to a concrete contribution pattern
(reference pack + fixtures, per CONTRIBUTING.md).

## By domain

| Domain | Coverage | Notes |
|---|---|---|
| Secrets detection | strong | regex set + triage; + **dev-artifact leak surface (Postman/Insomnia, .vscode/.idea, .http, devcontainer, swagger examples)**; + **connection-string pack (URL, JDBC, ADO.NET `Server=…;Password=…` — value-embedded, key-value patterns miss it)**; grows with provider patterns |
| Dependency CVEs | strong (live) | OSV API; + reachability analysis (present→used→dormant), Step 2.5 supply-chain hygiene, Step 2.7 beyond-CVEs (discontinued/compromised-history/dangerous-usage/vendored packs); measured by `supply-chain-vuln` + `dep-risk-vuln-app` fixtures |
| Injection (SQLi/XSS/cmd/path/SSTI/deser) | strong | Node/Python/Java/Ruby/PHP/Go packs + **C/C++ native (format strings, strcpy, system, overflow-to-alloc, TOCTOU)**; XXE, prototype pollution, NoSQL operator injection, ReDoS, open redirect, upload abuse, second-order flows, builder raw, multi-line |
| Auth/authz | strong | sessions, JWT (confusion/kid/PKCE), OAuth, **SAML (SWA/XSW, comment injection, recipients, loose knobs)**, IDOR; + route census (HTTP + gRPC/MQ/scheduled), mass assignment, trusted-header spoofing, TOCTOU races, WebSocket/SSE authz, **LDAP (anonymous binds, DN/filter injection — py + JNDI)**, **feature/plan capability gating (enforcement-point census, default-true, store staleness, public outbound-message endpoints — stack-agnostic, incident-converted 2026-09-23)** |
| Crypto | strong | usage-context judgment table; measured end-to-end by `crypto-vuln-app` fixture (ECB/DES/MD5/non-CSPRNG/TLS-off/weak-KDF + safe forms) |
| Config/headers/CORS/CI | strong | + postMessage/client-side handlers, weak-CSP/cookie-prefix/SRI review, CRLF, API4/API10, **WebAssembly loading discipline (WSTG 4.13 repo-detectable subset)** (`web-hardening-vuln` + `spa-vuln-app` fixtures) | |
| Containers & IaC | strong | Docker/compose/K8s (incl. **RBAC escalation verbs**) /Terraform; + **serverless/FaaS**; AWS IAM escalation-path pack; egress/NetworkPolicy + IMDSv2; fixtures: infra-vuln, iac-vuln-app, surface-vuln-app |
| Data exposure / logging | strong | A09 pack: audit events, log forging, verbosity; alerting-config checks (in-repo evidence first, "not assessed" fallback) |
| GraphQL APIs | good | `graphql-security`: introspection, depth limits, resolver authz, CSRF, batching |
| LLM / AI apps | good | `llm-security`: prompt injection/exfil, model deserialization, LLM keys, agent tools, telemetry; measured by `llm-vuln-app` fixture |
| Course/e-learning platforms | good | `course-platform-security`: gating truth, preview leaks, enrollment state machine, cohort scoping, moderation-queue student→admin XSS — persona-driven (public/student/admin); fixture `course-vuln-app` |
| Skill authoring | — | `skill-forge`: scaffold + authoring laws + blind-test protocol for building NEW custom skills without external dependencies |
| Insecure design (A04) | good | grep-anchored checklist + `flow-security` skill for flow-wise analysis (F1–F9 classes, flow-vuln-app fixture) |
| **Design-phase threat modeling (pre-code)** | good | `design-threat-review`: spec in → THREAT-MODEL.md out (actor×asset matrix, trust boundaries, STRIDE→detector mapping, audit contract); fixture `design-threat-review-vuln-app`; audit-time consumption via security-audit Phase 0 THREAT-MODEL.md hook |
| **Audit completeness enforcement** | good | security-audit Completeness gate v2 (actor×surface matrix, every cell ✅/🟢/⬜ dispositioned, NOT-ASSESSED listed by name) + census receipts (`hits=N dispositioned=N`) + enumeration discipline; incremental PR/diff audit mode (`pr_diff_scope.sh`) for early-stage delta audits |
| Mobile (Android/iOS/RN/Flutter) | good | `mobile-security` pack |
| Laravel/PHP | good | `laravel-security`: mass assignment, APP_KEY chain, Blade raw-output census (glob + disposition + privilege-direction triage), CSRF except; **Step 8: feature-flag gating (route vs UI/job, define-true defaults, Pennant staleness + purge) & outbound-email blast amplification (F9)** — incident-converted 2026-09-23; fixture `laravel-vuln-app` (21 rows) |
| Django/Python | good | `django-security`: raw()/extra(), mark_safe, `__all__` mass assignment, settings |
| ASP.NET / .NET | good | `dotnet-security`: Html.Raw/Blazor MarkupString XSS census, FromSqlRaw/Dapper/ADO SQLi (with the `FromSqlInterpolated` safe-API near-miss), BinaryFormatter/TypeNameHandling/machineKey→ViewState pack, `[AllowAnonymous]` census, Telerik CVE-2019-18935 via vuln-db; fixture `dotnet-vuln-app` |
| Rails/Ruby | good | `rails-security`: interpolated where, permit!, CSRF skips, secret_key_base |
| Spring/Java | good | `spring-security`: JPQL/MyBatis `${}`, th:utext, actuator, SecurityConfig |

## By language/manifest (dependency parser)

| Ecosystem | Parser | Notes |
|---|---|---|
| npm (all 3 lockfiles), pip (3), Bundler, Cargo, Composer, Go, Maven, NuGet, Pub, Gradle, Swift (SPM), Conan, Hex (mix.lock) | ✅ | heuristic parsers |
| Hex (mix.exs/lock), Cargo alt registries | ❌ | help wanted |

## Help wanted (priority order)

1. **More vuln-db entries** — ongoing weekly via KEV triage issues; incident-research batches (Metasploit-class waves) welcome — see `cve-research/references/notable-incidents.md`
2. **Real-world quarterly benchmarks** using `scripts/score_audit.py` (see `evals/run.md`); scoreboard rows from any agent-run round welcome
3. **Retry the 3 blocked e2e runs** (node-vuln-app-3, crypto-vuln-app, dep-manifests) when subagent models are available

Closed 2026-09-23 (knowledge-gap-closure round): `dotnet-security` skill (was #1 — GHSL gap), LDAP pack in auth-review (#1a — CodeQL diff), WebAssembly checks in config-hardening (#1b — WSTG 4.13), framework rows Flask-RESTful / Gin+sqlx / ASP.NET Web Forms (was #2), Telerik CVE-2019-18935 vuln-db entry, ADO.NET connection-string pattern in secrets-detection.

## Benchmark targets (quarterly, per evals/README.md)

Juice Shop (node) · Node Goof (deps) · Railsgoat (ruby) · WebGoat (java) · DVNA (node)
