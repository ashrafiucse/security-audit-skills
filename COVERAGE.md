# Coverage Map & Roadmap

Honest assessment of where the skills are strong and thin. Contributors: pick
anything from "Help wanted" — each item maps to a concrete contribution pattern
(reference pack + fixtures, per CONTRIBUTING.md).

## By domain

| Domain | Coverage | Notes |
|---|---|---|
| Secrets detection | strong | regex set + triage; grows with provider patterns |
| Dependency CVEs | strong (live) | OSV API; parser coverage below |
| Injection (SQLi/XSS/cmd/path/SSTI/deser) | strong | Node/Python/Java/Ruby/PHP/Go packs in `injection-flaws/references/`; + XXE, prototype pollution, NoSQL operator injection, ReDoS, open redirect, upload abuse, second-order/stored flows, query-builder raw sinks, multi-line construction |
| Auth/authz | strong | sessions, JWT, OAuth, IDOR; + route census, trusted-header spoofing, TOCTOU races, WebSocket/SSE authz |
| Crypto | strong | usage-context judgment table |
| Config/headers/CORS/CI | strong | |
| Containers & IaC | strong | Docker/compose/K8s/Terraform; measured by `iac-vuln-app` fixture (+CI workflow) |
| Data exposure / logging | good | A09 pack (audit events, log forging, verbosity); alerting config remains report-level |
| GraphQL APIs | good | `graphql-security`: introspection, depth limits, resolver authz, CSRF, batching |
| Insecure design (A04) | good | grep-anchored checklist (replay/idempotency, client-controlled money/scope, negative values, step-skipping) in `security-audit/references/owasp-top10.md`; judgment still required |
| Mobile (Android/iOS/RN/Flutter) | good | `mobile-security` pack |
| Laravel/PHP | good | `laravel-security`: mass assignment, APP_KEY chain, Blade, CSRF except |
| Django/Python | good | `django-security`: raw()/extra(), mark_safe, `__all__` mass assignment, settings |
| Rails/Ruby | good | `rails-security`: interpolated where, permit!, CSRF skips, secret_key_base |
| Spring/Java | good | `spring-security`: JPQL/MyBatis `${}`, th:utext, actuator, SecurityConfig |

## By language/manifest (dependency parser)

| Ecosystem | Parser | Notes |
|---|---|---|
| npm (all 3 lockfiles), pip (3), Bundler, Cargo, Composer, Go, Maven, NuGet, Pub, Gradle, Swift (SPM), Conan, Hex (mix.lock) | ✅ | heuristic parsers |
| Hex (mix.exs/lock), Cargo alt registries | ❌ | help wanted |

## Help wanted (priority order)

1. **More framework rows** in `injection-flaws/references/frameworks.md` (Ktor, NestJS, Django REST, Rails API modes…)
2. **More vuln-db entries** — ongoing weekly via KEV triage issues

## Benchmark targets (quarterly, per evals/README.md)

Juice Shop (node) · Node Goof (deps) · Railsgoat (ruby) · WebGoat (java) · DVNA (node)
