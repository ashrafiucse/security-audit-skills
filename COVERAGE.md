# Coverage Map & Roadmap

Honest assessment of where the skills are strong and thin. Contributors: pick
anything from "Help wanted" — each item maps to a concrete contribution pattern
(reference pack + fixtures, per CONTRIBUTING.md).

## By domain

| Domain | Coverage | Notes |
|---|---|---|
| Secrets detection | strong | regex set + triage; grows with provider patterns |
| Dependency CVEs | strong (live) | OSV API; parser coverage below |
| Injection (SQLi/XSS/cmd/path/SSTI/deser) | strong | Node/Python/Java/Ruby/PHP/Go packs in `injection-flaws/references/` |
| Auth/authz | strong | sessions, JWT, OAuth, IDOR |
| Crypto | strong | usage-context judgment table |
| Config/headers/CORS/CI | strong | |
| Containers & IaC | strong | Docker/compose/K8s/Terraform |
| Data exposure / logging | good | A09 pack (audit events, log forging, verbosity); alerting config remains report-level |
| GraphQL APIs | good | `graphql-security`: introspection, depth limits, resolver authz, CSRF, batching |
| Insecure design (A04) | thin | guided prompts only; no systematic method |
| Mobile (Android/iOS/RN/Flutter) | good | `mobile-security` pack |
| Laravel/PHP | good | `laravel-security`: mass assignment, APP_KEY chain, Blade, CSRF except |

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
