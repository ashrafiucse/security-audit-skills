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
