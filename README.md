# Security Audit Skills

[![CI](https://github.com/ashrafiucse/security-audit-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/ashrafiucse/security-audit-skills/actions/workflows/ci.yml)

A collection of agent skills for **security testing any codebase**. Clone this repo, plug it into your agent (pi, or any Agent Skills-compatible harness), and get a full security audit: secrets, vulnerable dependencies, injection flaws, auth bugs, crypto weaknesses, misconfigurations, container/IaC risks, and fresh CVE intelligence — with a prioritized, evidence-based report.

## What it does

Give it any project (any language, any stack) and it will:

1. **Map the stack** — languages, frameworks, dependency manifests, infra files
2. **Deep-scan** — secrets, CVEs in dependencies, injection flaws, auth/authz issues, weak crypto, config mistakes, Docker/K8s/Terraform risks, data exposure
3. **Triage** — severity-ranked findings with evidence (`file:line`), CWE mapping, and exploitability notes
4. **Report** — a `SECURITY-AUDIT.md` with concrete fix recommendations

## Skills

| Skill | Purpose |
|---|---|
| `security-audit` | Master orchestrator: full-project audit workflow, fix-verification (re-audit) mode, report format, optional tool bridges (gitleaks/semgrep/checkov… when installed) |
| `secrets-detection` | Hardcoded keys, tokens, passwords, private keys (fast regex scan + triage) |
| `dependency-vulns` | Dependency risk: live OSV CVE scanning + reachability (used vs dormant), supply-chain hygiene (dependency confusion, typosquats, provenance), and beyond-CVEs — discontinued/unfixable packages, compromised-release history, dangerous usage of safe packages, vendored copies invisible to manifest scanners |
| `injection-flaws` | SQLi, command injection, XSS (reflected + stored/second-order), path traversal, SSRF (incl. deferred/registered-callback), deserialization, SSTI, XXE, prototype pollution, NoSQL operator injection, ReDoS, open redirect, unsafe uploads + archive extraction, C/C++ native memory-safety sinks |
| `auth-review` | Authn/authz, route census (incl. gRPC/MQ/scheduled handlers), password storage, sessions, JWT (confusion/kid/PKCE), **SAML (signature wrapping, comment injection, recipient validation)**, OAuth, IDOR, mass assignment, CSRF, trusted-header spoofing, TOCTOU races, WebSocket/SSE authz |
| `crypto-review` | Weak ciphers/hashes, ECB, hardcoded keys/IVs, bad randomness |
| `config-hardening` | Headers (incl. weak-CSP review), cookie prefixes, SRI, CORS, cookies, TLS, debug modes, CI/CD pitfalls, postMessage/client-side handlers, API resource & consumption (API4/API10) |
| `container-iac-security` | Dockerfile, docker-compose, Kubernetes (incl. **RBAC escalate/bind/impersonate verbs**), Terraform/CloudFormation + AWS IAM privilege-escalation paths, **serverless/FaaS (IAM wildcards, authorizer gaps, trusted events)** |
| `graphql-security` | GraphQL abuse vectors: introspection/GraphiQL in prod, depth limits, resolver authz/IDOR, error leakage, batching, CSRF |
| `llm-security` | LLM/AI apps: prompt injection & data exfil, unsafe model deserialization (pickle/torch.load/LangChain), hardcoded LLM keys, over-powered agent tools, prompt/PII logging & telemetry |
| `flow-security` | Cross-endpoint business flows: state-machine violations (skip/replay/disorder), client-supplied data at terminal steps, association/chained IDOR, webhook replay, step-skipping via direct access, post-payment mutation, amount drift, privilege transitions between hops |
| `course-platform-security` | E-learning/course platforms, persona-driven: catalog gating truth (draft/private exposure), preview-vs-full-content leaks, enrollment state machines, cohort/multi-cohort access, admin-only surfaces |
| `skill-forge` | Authors NEW custom skills for this repo: scoping from personas/pains, scaffold script, authoring laws from the eval LEARNINGS, blind-test protocol, wiring checklist |
| `mobile-security` | Android manifest & WebView, iOS ATS/UserDefaults, RN/Flutter storage |
| `laravel-security` | Laravel: mass assignment, APP_KEY/` .env` RCE chain, DB::raw injection, CSRF `$except`, Blade `{!! !!}` |
| `django-security` | Django: `raw()`/`extra()` SQLi, `mark_safe`/`|safe` XSS, `fields='__all__'` mass assignment, settings misconfig |
| `rails-security` | Rails: interpolated `where`, `permit!`, `raw`/`html_safe`, CSRF skips, `send_file` traversal, `secret_key_base` |
| `spring-security` | Spring: JPQL concat, MyBatis `${}`, `th:utext`, CSRF/`permitAll`, Actuator over-exposure, Jackson defaultTyping |
| `data-exposure` | PII handling, secrets in logs, over-returning APIs, git history |
| `cve-research` | Live CVE research for the project's exact stack + versioned vuln knowledge base |

## Install

### Option A — global (recommended)

```bash
git clone https://github.com/ashrafiucse/security-audit-skills.git
cd security-audit-skills
./install.sh            # symlinks every skill into ~/.agents/skills
```

### Option B — per-project

```bash
git clone https://github.com/ashrafiucse/security-audit-skills.git
```

Then in your project's `.pi/settings.json`:

```json
{
  "skills": ["/absolute/path/to/security-skills/skills"]
}
```

### Option C — manual symlink

```bash
ln -s /path/to/security-skills/skills/security-audit ~/.agents/skills/security-audit
```

## Usage

Ask naturally:

> "Run a security audit on this project"

or force it explicitly:

```
/skill:security-audit
/skill:dependency-vulns
/skill:cve-research what's new for my stack?
```

The agent auto-loads the right skill when your request matches its description.

## Principles

- **Read-only by default.** Audit skills never modify, delete, or exploit anything — they read code and produce evidence-backed findings. Verified three ways: `scripts/audit_readonly.py` (CI-gated static gate over all executables + skill bash blocks), empirical sha256 hash-diff audits (scanners leave the tree byte-identical; the audit's only write is `SECURITY-AUDIT.md`), and a full external-source egress inventory at `skills/security-audit/references/external-sources.md` (the one real egress: OSV receives package@version pairs; offline mode avoids it).
- **Evidence over guesses.** Every finding cites `file:line` and is verified against surrounding context to suppress false positives.
- **Mapped to standards.** Findings reference CWE / CVE / OWASP Top 10 / CIS where applicable.
- **Progressive disclosure.** SKILL.md files stay lean; deep pattern databases live in `references/` and load only when needed.

## Keeping it current

This repo is designed to be updated as new vulnerabilities go public. See [MAINTENANCE.md](MAINTENANCE.md) for the update pipeline — **daily automated CISA KEV + NVD critical-CVE digests** (issues with pre-drafted entries), **live OSV.dev checks at scan time**, maintainer **notifications** on every actionable issue, and community miss-reports via issue templates. Consumers just `git pull`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Building a whole new skill? Load `skills/skill-forge/SKILL.md` and run its scaffold — it encodes every authoring law the evals have paid for. Every accepted detection pattern must ship with a test fixture in `evals/` so quality only goes up. Misses (user-reported or benchmark-found) are tracked in [evals/MISSES.md](evals/MISSES.md) until converted to pattern + fixture. Current gaps and roadmap: [COVERAGE.md](COVERAGE.md).

## License

MIT
