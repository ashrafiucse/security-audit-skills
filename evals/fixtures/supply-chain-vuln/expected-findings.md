# supply-chain-vuln — Expected findings

Ground truth for `evals/fixtures/supply-chain-vuln` (dependency confusion +
typosquats + lockfile-integrity matrix; see `dependency-vulns` Step 2.5).
Names are FAKE. Live registry checks (does `@acme-corp/auth-lib` resolve
publicly?) are network-dependent → treat as the CONFIRM step, not ground
truth.

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Typosquat — `lodash2` (edit-distance 1 from `lodash`, `-digit` clone shape) | package.json:6 | High (until verified legitimate) |
| 2 | Typosquat — `reqeusts` (transposed `requests`, classic typosquat shape) | package.json:7 | High (until verified legitimate) |
| 3 | Dependency confusion candidate — scoped/internal-looking `@acme-corp/auth-lib` that may resolve on the public registry | package.json:8 | Critical (if `npm view` succeeds) / High (unverified) |
| 4 | No lockfile — non-reproducible installs, transitive-swap risk | (absence of package-lock.json) | High |
| 5 | pip integrity NOT enforced — `requirements.txt` has no `--require-hashes` (ToB matrix: pip verifies only with extra steps) | requirements.txt:- | Medium |
| 6 | Composer content-integrity NOT verified even with lockfile present (ToB no-verify bucket; `dist` entries carry no shasum) — informational ecosystem note | composer.lock:- | Info (note) |
| 7 | Caret-wide ranges in prod manifest with no lockfile (floating install surface; pin via lockfile at minimum) | package.json:5 | Medium |

## Must NOT trigger (near-misses)

- `express@^4.19.2` — popular package, correct spelling, nothing to flag beyond normal dep checks
- `requirements-locked.txt` — pip run WITH `--hash=sha256:` pins and `--require-hashes` discipline; this is the SAFE counterpart to row 5, not a second missing-hashes finding (do not double-report)
