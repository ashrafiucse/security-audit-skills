# Security Audit — llm-vuln-app (triage conversion round, issues #58-#61)
Date: 2026-10-05 | Scope: working tree (fixture) | Auditor: security-skills dev (IN-PROCESS run — ground-truth-aware artifact validation, not blind recall; see scoreboard label)
Trigger: NVD digest #58 — MindSearch CVE-2026-105135 class conversion: model-emitted code executed verbatim on an unauthenticated endpoint → llm-security §5 model-emitted-code bullet (agent_exec.py plant + sandboxed/authenticated safe counterpart).

## Stack
Python LLM app (app.py: Anthropic client, pickled model load, torch.load, exfil fetch tool, PythonREPLTool agent, RPyC serving) + MCP server (mcp_server.py: filesystem/exec/fetch tools, SSE transport, connect endpoint) + Mooncake-style metadata server (metadata_server.py) + MindSearch-style planner (agent_exec.py) + safe counterparts (safe_app.py, safe_mcp_server.py, safe_metadata_server.py, safe_agent_exec.py). requirements.txt: unpinned deps + `mooncake==0.3.12`.

## Summary
| Severity | Count |
|---|---|
| Critical | 9 |
| High | 6 |

## Findings
### SEC-001: Hardcoded Anthropic API key + HF token — CRITICAL
- **Where:** `app.py:13`, `app.py:15` — **CWE-798** — `sk-ant-api03-...` and `hf_...` in source (fake eval plants; the pattern is the finding).

### SEC-002: Unsafe model deserialization — pickle.load on user-supplied path — CRITICAL
- **Where:** `app.py:18-22` — **CWE-502** — pickled payloads execute on load.

### SEC-003: torch.load without weights_only=True — arbitrary code execution — CRITICAL
- **Where:** `app.py:24-26` — **CWE-502** — use `weights_only=True` or safetensors.

### SEC-004: Exfil/SSRF tool — requests.get with model-chosen URL, no allowlist — HIGH
- **Where:** `app.py:29-31` — **CWE-918** — prompt injection → egress channel.

### SEC-005: PythonREPLTool on an agent driven by untrusted chat — CRITICAL
- **Where:** `app.py:34` — **CWE-94** — prompt injection → code exec one step away.

### SEC-006: Prompt injection — user input concatenated into instruction prompt with tools attached — HIGH
- **Where:** `app.py:38-41` — **CWE-1427** — delimit/allowlist absent.

### SEC-007: Unpinned dependencies + no lockfile — HIGH
- **Where:** `requirements.txt:-` — **CWE-1104** — non-reproducible, supply-chain swap risk.

### SEC-008: MCP filesystem tool — raw open(path).read() on tool argument — CRITICAL
- **Where:** `mcp_server.py:10-12` — **CWE-22** — any client reads any file the process can.

### SEC-009: MCP exec tool — subprocess.run(command, shell=True) as a tool — CRITICAL
- **Where:** `mcp_server.py:16-18` — **CWE-78** — RCE by design.

### SEC-010: MCP fetch tool echoes raw remote content into model context — HIGH
- **Where:** `mcp_server.py:24-26` — **CWE-1427** — indirect prompt injection rides the tool result.

### SEC-011: MCP SSE transport started with no auth layer — HIGH
- **Where:** `mcp_server.py:43` — **CWE-306** — unauthenticated callers invoke every tool.

### SEC-012: MCP connect endpoint grants server sessions by ID possession only — HIGH
- **Where:** `mcp_server.py:33-38` — **CWE-862** — no per-server ACL at connect time (obot CVE-2026-101084 pattern).

### SEC-013: Serving-stack RPC exposed unauthenticated with pickle — CRITICAL
- **Where:** `app.py:44-64` — **CWE-502** — `ThreadedServer(hostname="0.0.0.0", protocol_config={"allow_pickle": True})` (LightLLM CVE-2026-103040/103041 pattern).

### SEC-014: Unauthenticated LLM control-plane HTTP service — CRITICAL
- **Where:** `metadata_server.py:10-24` — **CWE-306** — `/metadata` GET/POST/DELETE with no auth + `app.run(host="0.0.0.0")` (CVE-2026-103765 class; `requirements.txt:9` pins `mooncake==0.3.12` < 0.3.13 — also carries CVE-2026-103764 memory R/W).

### SEC-015: Model-emitted code executed verbatim on an unauthenticated endpoint — CRITICAL
- **Where:** `agent_exec.py:17-34` — **CWE-94/306** — `extract_code()` takes the first markdown fence of the WHOLE model response; `exec(command, GLOBAL_DICT, LOCAL_DICT)` runs it with process globals + full `__builtins__`, no sandbox/AST allowlist; `@app.post("/solve")` has NO auth (upstream default bind 0.0.0.0:8002) — anyone who reaches the port runs OS commands as the server user (MindSearch CVE-2026-105135 class). Safe shape (`safe_agent_exec.py`): `run_sandboxed()` AST allowlist + `{"__builtins__": {}}` + endpoint behind `Depends(verify_api_key)`.
