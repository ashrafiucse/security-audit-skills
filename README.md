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
| `security-audit` | Master orchestrator: full-project audit workflow + report format |
| `secrets-detection` | Hardcoded keys, tokens, passwords, private keys (fast regex scan + triage) |
| `dependency-vulns` | Known-vulnerable dependencies via OSV.dev (CVE/GHSA/PYSA/RUSTSEC…) |
| `injection-flaws` | SQLi, command injection, XSS, path traversal, SSRF, deserialization, SSTI |
| `auth-review` | Authn/authz, password storage, sessions, JWT, OAuth, IDOR, CSRF |
| `crypto-review` | Weak ciphers/hashes, ECB, hardcoded keys/IVs, bad randomness |
| `config-hardening` | Headers, CORS, cookies, TLS, debug modes, CI/CD pitfalls |
| `container-iac-security` | Dockerfile, docker-compose, Kubernetes, Terraform/CloudFormation |
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

- **Read-only by default.** Audit skills never modify, delete, or exploit anything — they read code and produce evidence-backed findings.
- **Evidence over guesses.** Every finding cites `file:line` and is verified against surrounding context to suppress false positives.
- **Mapped to standards.** Findings reference CWE / CVE / OWASP Top 10 / CIS where applicable.
- **Progressive disclosure.** SKILL.md files stay lean; deep pattern databases live in `references/` and load only when needed.

## Keeping it current

This repo is designed to be updated as new vulnerabilities go public. See [MAINTENANCE.md](MAINTENANCE.md) for the update pipeline (CISA KEV, NVD, OSV/GHSA feeds, weekly automation via GitHub Actions). Consumers just `git pull`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every accepted detection pattern must ship with a test fixture in `evals/` so quality only goes up.

## License

MIT
