# iac-vuln-app — Expected findings

Ground truth for `evals/fixtures/iac-vuln-app` (Kubernetes, Terraform, GitHub
Actions). Exercises `container-iac-security` and the CI/CD section of
`config-hardening`. Values are documented fakes (`Fake4EvalsDoNotUse`).

| # | Category | Where | Severity |
|---|---|---|---|
| 1a | Privileged container | deployment.yaml:14 | Critical |
| 1b | Untagged/rolling image tag (`:latest`) | deployment.yaml:12 | Medium |
| 1c | Container runs as root (`runAsUser: 0`) | deployment.yaml:15 | High |
| 1d | Plaintext secret in pod spec env | deployment.yaml:18 | High |
| 1e | Host root mounted writable into pod (`hostPath: /`) | deployment.yaml:21-25 | Critical |
| 2a | SSH (22) open to `0.0.0.0/0` | main.tf:12 | High |
| 2b | DB storage unencrypted at rest | main.tf:19 | High |
| 2c | Hardcoded DB password | main.tf:21 | Critical |
| 2d | IMDSv1 allowed on URL-fetching workload (`http_tokens = "optional"`) — metadata credential theft pairs with SSRF | main.tf:28-31 | High |
| 2e | `curl | sh` in instance bootstrap | main.tf:35 | High |
| 4 | No NetworkPolicy restricting egress of `url-fetcher` (absence finding — check for `kind: NetworkPolicy` / `policyTypes: Egress` anywhere) | fetcher-deployment.yaml:3-12 (whole repo) | Medium |
| 3a | `pull_request_target` — fork PRs run with base-repo secrets | deploy.yml:4 | Critical (combined with 3b) |
| 3b | Checkout of untrusted PR head ref | deploy.yml:16 | Critical (combined with 3a) |
| 3c | Overbroad token (`contents: write-all`) | deploy.yml:8 | Medium |
| 3d | Action pinned by tag, not commit SHA | deploy.yml:14 | Medium |
| 3e | `curl | sh` in workflow | deploy.yml:20 | High |
| 3f | Workflow script injection — `github.event.pull_request.title` interpolated inside `run:` (PR title = shell payload) | deploy.yml:18 | Critical |

## Must NOT trigger (near-misses — `hardened-deployment.yaml`)

- Digest-pinned image in fetcher-deployment.yaml (`@sha256:`) — no untagged-tag finding for it

- `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `drop: ["ALL"]` — the hardened pod is the safe form
- Secret via `secretKeyRef` (not plaintext env)
- Digest-pinned image (`@sha256:`) — untagged-tag finding does not apply
- Resource limits present — no missing-limits finding
