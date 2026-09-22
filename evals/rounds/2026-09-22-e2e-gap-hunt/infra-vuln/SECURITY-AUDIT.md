# Security Audit — infra-vuln
Date: 2026-09-22 | Scope: working tree | Auditor: security-skills v$(git describe --tags --always 2>/dev/null || echo dev)
Knowledge base: 36 vuln-db entries (newest 2025-03-21) | Live checks: OSV.dev + CISA KEV — NOT RUN (no network in this session)

## Stack
Infra-only fixture: 1 Dockerfile (Node app image) + 1 docker-compose.yml (app + postgres:13).
No application source, no dependency manifests, no K8s/Terraform/CI configs.
Entry surfaces: app port 3000 published, DB port 5432 published to host network.

## Summary
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | 1 |
| Low | 2 |

**Chains (Phase 2.5):**
- **Container-escape trifecta — SEC-005 + SEC-006 + SEC-007**: privileged mode + docker.sock + host-root mount on the SAME container. Any code execution inside the app (note SEC-002/SEC-004 supply-chain risk feeding exactly that) → spawn a privileged sibling container or write directly to host FS → **host root**. Each component alone is Critical; combined they are one step from app compromise to host compromise.
- **Reachable default-cred DB — SEC-008 + published ports**: `5432:5432` binds 0.0.0.0 by default; `postgres/postgres` is the first credential pair every scanner tries → network-adjacent DB access without touching the app.
- **Baked secret readable in-place — SEC-003 + SEC-001**: the root-running process (and any exec in the container) reads `DATABASE_URL` from the image layer; rotation is impossible without rebuilding (history/old images keep it).

## Findings

### SEC-001: Container runs as root (no USER directive) — HIGH
- **Where:** `Dockerfile:3-5` (no `USER` anywhere in file)
- **CWE:** CWE-250 (Execution with Unnecessary Privileges); OWASP A05
- **Evidence:**
  ```dockerfile
  # SEC-01: runs as root (no USER)
  FROM node:latest
  ```
  (grep `USER` over the file → 0 matches)
- **Impact:** every process in the container (including the npm-installed supply chain) runs as UID 0 — maximizes the blast radius of any app-level bug and of the mounts in SEC-006/007.
- **Fix:** `RUN groupadd -r app && useradd -r -g app app` + `COPY --chown=app:app . .` + `USER app`.
- **References:** CWE-250

### SEC-002: Untagged/rolling base image (`node:latest`) — MEDIUM
- **Where:** `Dockerfile:5`
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components); OWASP A06
- **Evidence:**
  ```dockerfile
  FROM node:latest
  ```
- **Impact:** non-reproducible builds — the base (and its vulnerability set) silently changes between builds; no way to pin/trust what shipped.
- **Fix:** pin a digest + version, e.g. `FROM node:22.11@sha256:<digest>`; update deliberately.

### SEC-003: Secret baked into image layer — CRITICAL
- **Where:** `Dockerfile:8`
- **CWE:** CWE-798 (Hardcoded Credentials); OWASP A02/A05
- **Evidence:**
  ```dockerfile
  ENV DATABASE_URL=postgres://app:Fake4EvalsDoNotUse@db.internal.example.com/shop
  ```
  (value here is an eval fixture fake — the PATTERN is the finding; a real value makes it directly exploitable)
- **Impact:** `ENV` persists in image layers and `docker history`/`docker inspect` of any copy; deleting it later does not scrub layers. Anyone with pull/read access to the image has DB credentials.
- **Fix:** mount at runtime from a secret manager (`docker run --env-file` from a vault, compose `secrets:`, or `DATABASE_URL` injected by the orchestrator); rotate the credential — rebuilding without it does not un-leak it.

### SEC-004: `curl | sh` in build — HIGH
- **Where:** `Dockerfile:12`
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere); OWASP A08/A06
- **Evidence:**
  ```dockerfile
  RUN curl -s https://get.example-example.com/install.sh | bash   # SEC-04: curl | sh
  ```
- **Impact:** arbitrary remote code executed into every build, no integrity check; compromise of that host (or DNS) = compromise of the image. Chain feeder for the escape trifecta (Summary).
- **Fix:** download, verify checksum/signature, then execute; or vendor the installer script into the repo.
- **References:** supply-chain guidance in `dependency-vulns` Step 2.7 (curl|sh class)

### SEC-005: Privileged container — CRITICAL
- **Where:** `docker-compose.yml:7`
- **CWE:** CWE-250; OWASP A05
- **Evidence:**
  ```yaml
  privileged: true                    # SEC-05: privileged container
  ```
- **Impact:** all capabilities, host devices, and kernel-surface access — equivalent to near-host execution; with `SEC-004` (remote code in build) it completes a trivial host-compromise chain.
- **Fix:** remove; if a specific capability is genuinely needed, `cap_add: <that one>` with justification.

### SEC-006: Docker socket mounted into container — CRITICAL
- **Where:** `docker-compose.yml:9`
- **CWE:** CWE-250 / CWE-668; OWASP A05
- **Evidence:**
  ```yaml
  - /var/run/docker.sock:/var/run/docker.sock   # SEC-06: docker.sock mount
  ```
- **Impact:** the Docker API = control of every container on the host; any code exec in the app container can spawn a privileged sibling mounting `/` → **host root**.
- **Fix:** remove the mount; use a rootless sidecar or agent (e.g., docker socket proxy limited to needed endpoints) if Docker control is truly required.

### SEC-007: Host root filesystem mounted (writable) — CRITICAL
- **Where:** `docker-compose.yml:10`
- **CWE:** CWE-732 (Incorrect Permission Assignment); OWASP A05
- **Evidence:**
  ```yaml
  - /:/hostpath                     # SEC-07: host root mounted
  ```
- **Impact:** container process can read AND write the entire host filesystem (no `:ro`): drop SSH `authorized_keys`, patch binaries, exfiltrate `/etc/shadow` — direct host takeover, no escape needed.
- **Fix:** remove; if host files are genuinely needed, mount the specific path read-only (`:/path:ro`).

### SEC-008: Default credentials on DB with published port — HIGH
- **Where:** `docker-compose.yml:12,16,18`
- **CWE:** CWE-798; OWASP A07/A05
- **Evidence:**
  ```yaml
  - DB_PASSWORD=postgres            # SEC-08: default credential
  ...
  - POSTGRES_PASSWORD=postgres      # SEC-08b
  ports:
  - "5432:5432"                     # SEC-09: DB published to host/network
  ```
- **Impact:** published ports bind 0.0.0.0 by default — anything that can reach the host gets a Postgres login prompt with `postgres/postgres`. Same compose file ships a root/privileged app container, so DB contents are not the ceiling.
- **Fix:** strong unique password from a secret (`compose secrets:` / env from vault); remove the `5432` port mapping entirely (compose network DNS reaches the DB); if debug access is required, bind `127.0.0.1:5432:5432` temporarily.

### SEC-009: `postgres:13` past/near end-of-life — LOW (Possible — needs verification)
- **Where:** `docker-compose.yml:14`
- **CWE:** CWE-1104; OWASP A06
- **Evidence:**
  ```yaml
  image: postgres:13
  ```
- **Impact:** PostgreSQL 13 community EOL was November 2025 — past EOL means no security fixes ever (verify current status: live endoflife.date check NOT RUN in this session).
- **Fix:** upgrade to a supported major (16/17) — `postgres:17`; plan data migration.

### SEC-010: No HEALTHCHECK — LOW
- **Where:** `Dockerfile` (whole file — absence)
- **CWE:** CWE-754 (Improper Check for Exceptional Conditions); hygiene
- **Evidence:** grep `HEALTHCHECK` → 0 matches in Dockerfile.
- **Impact:** orchestrator cannot detect a wedged app; availability hygiene only.
- **Fix:** `HEALTHCHECK CMD curl -fs http://localhost:3000/health || exit 1` (or the compose equivalent).

## What looks good
- The app image builds from a plain `COPY . .` with no `.env` or key files present in the build context as shipped (this fixture's context is only these two files — but see below).
- `postgres:13` is at least version-pinned (not `:latest`), unlike the app image.
- No `network_mode: host`, no `cap_add` grants, no K8s/TF surfaces present.

## What would make this worse (near-chains)
- `COPY . .` with **no `.dockerignore`** (verified absent): any future `.env`, `node_modules`, or `.git` added to the context ships straight into the image (pairs with SEC-003). Add a `.dockerignore`.
- `RUN npm install` unpinned with no lockfile (`package.json` absent here; when added, this becomes a reproducibility/supply-chain finding per `dependency-vulns` Step 2).

## OWASP completeness gate (A01–A10)
A01/A03/A04/A07 (code-level): no application source in scope — **not assessed**.
A02: covered (SEC-003, SEC-008). A05: covered (SEC-001/002/005/006/007/008/010). A06: partially covered (SEC-002/009; OSV/KEV live checks not run — no network). A08: covered (SEC-004). A09: no logging surface defined in infra files — **not assessed** (app code absent). A10: no outbound-fetch surface defined in these files — n/a.

## Recommended fix order
1. **SEC-005/006/007** (critical, S effort) — remove `privileged`, docker.sock, and `/` mounts: kills the escape trifecta in one edit.
2. **SEC-003** (critical, M) — move `DATABASE_URL` to runtime secret + rotate the credential.
3. **SEC-008** (high, S) — strong DB password + drop the `5432` port mapping.
4. **SEC-004** (high, M) — replace `curl | sh` with verified download.
5. **SEC-001/002/010** (high/medium/low, S each) — non-root USER, pinned digest, HEALTHCHECK, add `.dockerignore`.
6. **SEC-009** (low, L) — plan postgres major upgrade after verification.
