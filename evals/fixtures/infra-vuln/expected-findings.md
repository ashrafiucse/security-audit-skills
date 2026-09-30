# infra-vuln — Expected findings

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Container runs as root | Dockerfile:4 | High |
| 2 | `node:latest` untagged base | Dockerfile:5 | Medium |
| 3 | Secret baked into image ENV layer (DB creds in connection string) | Dockerfile:8 | Critical |
| 4 | curl \| sh in build | Dockerfile:12 | High |
| 5 | privileged: true | docker-compose.yml:7 | Critical |
| 6 | docker.sock mounted | docker-compose.yml:9 | Critical |
| 7 | Host root path mounted writable | docker-compose.yml:10 | Critical |
| 8 | Default credentials (postgres) | compose:12,16 | High (published ports) |
| 9 | Postgres port published to host | docker-compose.yml:18 | High |
| 10 | No `HEALTHCHECK` in Dockerfile — orchestrator cannot detect a wedged app (file-level anchor) | Dockerfile:- | Low |
| 11 | AI agent/MCP platform (obot quickstart pattern) with auth disabled AND admin port published — any unauthenticated network caller becomes the synthetic Owner+Admin of the agent plane (CVE-2026-101065); chain: docker.sock mounted in the same service → MCP tool runtime reaches host Docker → host-root takeover | docker-compose.yml:21-28 | Critical |

## Must NOT trigger (near-misses — `hardened-compose.yml`)

- `OBOT_AUTH_ENABLED=true` + `expose:` (no host port mapping) — auth on and unreachable from outside the compose network
- Published port alone is NOT this finding (row 9 precedent — judge by what the port exposes + auth state); auth-off flag alone on an unpublished dev service → downgrade to High config smell, not the Critical chain
- No quoted `"host:container"` port mapping occurs in `hardened-compose.yml`
