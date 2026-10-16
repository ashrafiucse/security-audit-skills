# Security Audit — llm-vuln-app (issue #86 round)
Date: 2026-10-16 | Scope: working tree (fixture) | Auditor: security-skills dev (IN-PROCESS run — ground-truth-aware artifact validation, not blind recall; see scoreboard label)
Trigger: issue #86 — Archon CVE-2026-111322 permission-bypass amplifier added to llm-security §5 (bypassPermissions census) + row-15 extension; 15 prior rows re-verified.

## Stack
Python LLM app + MCP server + Mooncake metadata server + MindSearch-style planner (agent_exec.py) + safe counterparts; requirements unpinned (live OSV informational).

## Summary
| Severity | Count |
|---|---|
| Critical | 10 |
| High | 6 |

## Findings
### SEC-001: Hardcoded Anthropic API key — CRITICAL
- **Where:** `app.py:13` — Hardcoded Anthropic API key.
### SEC-01b: Hardcoded Hugging Face token — CRITICAL
- **Where:** `app.py:15` — Hardcoded Hugging Face token.
### SEC-002: Unsafe model deserialization  — CRITICAL
- **Where:** `app.py:18-22` — Unsafe model deserialization — `pickle.load` on user-supplied path.
### SEC-003: `torch.load` without `weights_only=True`  — CRITICAL
- **Where:** `app.py:24-26` — `torch.load` without `weights_only=True` — arbitrary code execution.
### SEC-004: Exfil/SSRF tool  — HIGH
- **Where:** `app.py:29-31` — Exfil/SSRF tool — `requests.get(url)` with model-chosen URL, no allowlist.
### SEC-005: `PythonREPLTool` on an agent driven by untrusted chat (prompt injectio — CRITICAL
- **Where:** `app.py:34` — `PythonREPLTool` on an agent driven by untrusted chat (prompt injection → code exec).
### SEC-006: Prompt injection  — HIGH
- **Where:** `app.py:38-41` — Prompt injection — user input concatenated into the instruction prompt with tools attached.
### SEC-007: Unpinned dependencies + no lockfile  — HIGH
- **Where:** `requirements.txt:-` — Unpinned dependencies + no lockfile — non-reproducible, supply-chain swap risk (file-level anchor).
### SEC-008: MCP filesystem tool  — CRITICAL
- **Where:** `mcp_server.py:10-12` — MCP filesystem tool — raw `open(path).read()` on the tool argument: any client reads any file the process can (.env, keys).
### SEC-009: MCP exec tool  — CRITICAL
- **Where:** `mcp_server.py:16-18` — MCP exec tool — `subprocess.run(command, shell=True)` exposed as a tool: RCE by design.
### SEC-010: MCP fetch tool echoes raw remote content into the model context  — HIGH
- **Where:** `mcp_server.py:24-26` — MCP fetch tool echoes raw remote content into the model context — indirect prompt injection rides the tool result.
### SEC-011: MCP SSE transport started with no auth layer  — HIGH
- **Where:** `mcp_server.py:43` — MCP SSE transport started with no auth layer — unauthenticated callers invoke every tool.
### SEC-012: MCP connect endpoint grants server sessions by ID possession only  — HIGH
- **Where:** `mcp_server.py:33-38` — MCP connect endpoint grants server sessions by ID possession only — no per-server ACL at connect time; restricted MCP servers (stored OAuth credential.
### SEC-013: Serving-stack RPC exposed unauthenticated with pickle  — CRITICAL
- **Where:** `app.py:44-64` — Serving-stack RPC exposed unauthenticated with pickle — `ThreadedServer(hostname="0.0.0.0", protocol_config={"allow_pickle": True})`, no authenticator.
### SEC-014: Unauthenticated LLM control-plane HTTP service  — CRITICAL
- **Where:** `metadata_server.py:10-24` — Unauthenticated LLM control-plane HTTP service — Mooncake-style `/metadata` server: GET/POST/DELETE with NO auth (`get_json(force=True)` overwrite, `M.
### SEC-015: Model-emitted code executed verbatim on an unauthenticated endpoint +  — CRITICAL
- **Where:** `agent_exec.py:17-39` — Model-emitted code executed verbatim on an unauthenticated endpoint + permission-bypass amplifier — MindSearch-style planner: `extract_code()` takes t.
