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
| Data exposure / logging | partial | log-forging & audit-event checks thin (OWASP A09) |
| Insecure design (A04) | thin | guided prompts only; no systematic method |
| Mobile (Android/iOS) | none | help wanted |

## By language/manifest (dependency parser)

| Ecosystem | Parser | Notes |
|---|---|---|
| npm (all 3 lockfiles), pip (3), Bundler, Cargo, Composer, Go, Maven, NuGet, Pub | ✅ | heuristic parsers |
| Gradle lockfile, Conan, Swift, Hex, Cargo alt registries | ❌ | help wanted |

## Help wanted (priority order)

1. **Gradle + Swift + Conan lockfile parsers** in `osv_scan.py`
2. **A09 logging pack**: log-forging regexes, audit-event checklist per framework
3. **GraphQL/API-specific checks**: introspection in prod, missing depth/complexity limits, batch abuse
4. **Mobile pack**: Android manifest (exported components, backup flags), iOS plist (ATS off, weak storage)
5. **More framework rows** in `injection-flaws/references/frameworks.md` (Vue, Angular, Svelte, FastAPI, Gin, Echo, Symfony…)
6. **More vuln-db entries** — start from open triage issues (KEV label)

## Benchmark targets (quarterly, per evals/README.md)

Juice Shop (node) · Node Goof (deps) · Railsgoat (ruby) · WebGoat (java) · DVNA (node)
