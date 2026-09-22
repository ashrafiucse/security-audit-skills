# Security Audit — supply-chain-vuln
Date: 2026-09-22 | Scope: working tree @433fb22 (fixture dir) | Auditor: security-skills v1.2.0-31-g433fb22-dirty
Knowledge base: 36 vuln-db entries (newest 2026-09-11) | Live checks: OSV.dev + CISA KEV — NOT RUN (no network)

## Stack
Single-file npm project: `package.json` with 4 dependencies (`lodash2`, `reqeusts`, `@acme-corp/auth-lib`, `express@^4.19.2`). No application source code, no lockfile, no infra/CI config, no scripts. Audit surface = manifest hygiene + supply-chain risk only.

## Summary
| Severity | Count |
|---|---|
| Critical | 0 (1 escalates to Critical on registry verification) |
| High | 4 |
| Medium | 0 |
| Low | 0 |

Completed chains: **none fully** — "typosquat/confusion + no lockfile → arbitrary code at install time" is almost complete (no CI config in-repo to confirm install-time credential exposure); see "What would make this worse".

## Findings

### SEC-001: Typosquat — `lodash2` (digit-suffixed clone of `lodash`) — HIGH (until verified legitimate)
- **Where:** `package.json:6`
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components) / CWE-1357 (Reliance on Untrusted Components)
- **Evidence:**
  ```json
  "lodash2": "^1.0.2",
  ```
- **Impact:** Exact typosquat shape from the known hijack families (`-digit` suffixed clone of a top-10 package): if this is not a package you deliberately own/verified, installing it executes its code (including `postinstall`) with developer/CI credentials — token theft, backdoored builds. A caret range with no lockfile (SEC-004) means whatever version resolves at install time is what runs.
- **Fix:** Delete the dependency; if a `lodash2` feature was intended, identify the real need and use the legitimate `lodash` (or `lodash-es`) pinned via a lockfile. Verify first (see action below) and rotate any credentials that existed while it was installed.
- **References:** dependency-vulns Step 2.5 (typosquat heuristics)

### SEC-002: Typosquat — `reqeusts` (transposed `requests`) — HIGH (until verified legitimate)
- **Where:** `package.json:7`
- **CWE:** CWE-1104 / CWE-1357
- **Evidence:**
  ```json
  "reqeusts": "^2.88.0",
  ```
- **Impact:** Classic transposition typosquat, and the `^2.88.0` range mimics the real `request` npm package's version line — a shape designed to look intentional in review. Same install-time code-execution risk as SEC-001. Note also: even the *correct* targets are wrong here — `request` is deprecated/unmaintained (dangerous-packages pack) and `requests` is a Python package, not npm.
- **Fix:** Remove; use a maintained HTTP client (`fetch`/native, `undici`, `got`, `axios`) pinned by lockfile.
- **References:** dependency-vulns Step 2.5; references/dangerous-packages.md §1

### SEC-003: Dependency-confusion candidate — scoped/internal-looking `@acme-corp/auth-lib` — HIGH (Possible — needs verification; escalates to CRITICAL if it resolves on the public registry)
- **Where:** `package.json:8`
- **CWE:** CWE-1357 (dependency confusion)
- **Evidence:**
  ```json
  "@acme-corp/auth-lib": "^3.2.1",
  ```
- **Impact:** If the `@acme-corp` npm scope is not registered/owned on the public registry, ANYONE can publish `@acme-corp/auth-lib` — and this project (no lockfile, no registry pinning) will install the attacker's version. It is an **authentication library**: attacker-controlled auth code = credential/token interception and full account takeover of whatever authenticates through it.
- **Fix / verification (no network in this audit — run these):**
  ```bash
  npm view @acme-corp/auth-lib versions --json   # SUCCEEDS = Critical: namespace not protected
  ```
  If it resolves publicly: remove immediately, register the org scope on npm (or use a private registry/proxy with `@acme-corp:registry` pinning in `.npmrc`), rotate any credentials handled by the package. If `npm view` fails (not on public registry) and your private registry serves it: add the registry pin anyway — the unprotected state is the vulnerability.
- **References:** dependency-vulns Step 2.5 (dependency confusion)

### SEC-004: No lockfile — non-reproducible installs, no integrity pinning — HIGH
- **Where:** `package.json` (whole manifest; `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` absent — verified in Phase 0)
- **CWE:** CWE-1104 / CWE-1357
- **Evidence:** Phase 0 manifest census returned exactly one file (`package.json`); no lockfile exists. Caret ranges on all four dependencies (`^…`) resolve at install time.
- **Impact:** Every install resolves versions fresh: a malicious/renamed/attacker-published package (SEC-001/002/003 all exploit exactly this window) slips in silently, and no `integrity` hash exists to detect it. This finding is the multiplier that turns the three name findings from "suspicious" into "arbitrary code at install time" (tagged `chain-critical`).
- **Fix:** `npm install --package-lock-only` to generate the lockfile, commit it, and use `npm ci` in CI (never `npm install`); add `integrity` verification (default in lockfile) and consider `--ignore-scripts` for CI installs.
- **References:** dependency-vulns Step 2 (manifest hygiene), Step 2.5 (provenance)

## What looks good
- `express@^4.19.2` — correct spelling, maintained major, sensible range (package.json:9)
- `private: true` (package.json:3) — blocks accidental npm publish of this project itself
- No top-level lifecycle scripts (`pre`/`postinstall`) declared in the manifest — though dependency-internal scripts cannot be inspected without `node_modules`

## What would make this worse (almost-complete chains)
- Typosquat/confusion (SEC-001/002/003) + no lockfile (SEC-004) + CI with secrets = **full repo/package takeover at install time** — no CI config exists in this fixture to confirm the secrets component; in a real project, treat this as the primary chain.
- No `.npmrc` registry pinning for the `@acme-corp` scope — even a legitimate private package resolves publicly if the scope is unprotected.

## Recommended fix order
1. SEC-003 (verify `@acme-corp/auth-lib` registry resolution — 1 command; escalates to Critical if public) →
2. SEC-001 + SEC-002 (delete both typosquats; rotate dev credentials if ever installed) →
3. SEC-004 (generate + commit lockfile; `npm ci` in CI; `--ignore-scripts` where feasible)

## Not assessed
- Live OSV/CISA-KEV/EOL checks — no network in this audit (would also return nothing for the three fake names; `express` range is within current 4.x)
- OWASP categories with code surface (A01/A02/A03/A04/A07/A09/A10) — no source code exists in this fixture
