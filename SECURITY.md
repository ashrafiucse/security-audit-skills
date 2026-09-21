# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| latest release (`v1.x`) + `main` | ✅ |
| older tags | ❌ — `git pull` / upgrade |

## Reporting a vulnerability in these skills

Use GitHub's **private vulnerability reporting** on this repo
(Security → Report a vulnerability). Please include:

- Which skill / file is affected
- A minimal fixture that reproduces the problem
- Why the outcome is wrong (miss, false positive, or unsafe behavior)

**Do not open a public issue for exploitable flaws in the skills themselves.**
Triaged within 7 days; coordinated disclosure otherwise.

## Scope

This policy covers the *skills repository*. If an audit of **your** project
finds vulnerabilities, that's your remediation work — report misses via the
`missed-finding` issue template instead.

## Safe usage

All skills are read-only analyzers by design (see `CONTRIBUTING.md` ground
rules). They never execute project code, never exploit findings, and the only
file they create is `SECURITY-AUDIT.md`. Review skill content before loading
skills from any source — including this one.
