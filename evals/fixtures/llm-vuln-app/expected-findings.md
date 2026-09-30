# llm-vuln-app — Expected findings

Ground truth for `evals/fixtures/llm-vuln-app` (LLM/AI application security,
per `llm-security` skill). Live OSV results informational only — deps are
intentionally unpinned.

| # | Category | Where | Severity |
|---|---|---|---|
| 1 | Hardcoded Anthropic API key | app.py:13 | Critical |
| 1b | Hardcoded Hugging Face token | app.py:15 | Critical |
| 2 | Unsafe model deserialization — `pickle.load` on user-supplied path | app.py:18-22 | Critical |
| 3 | `torch.load` without `weights_only=True` — arbitrary code execution | app.py:24-26 | Critical |
| 4 | Exfil/SSRF tool — `requests.get(url)` with model-chosen URL, no allowlist | app.py:29-31 | High |
| 5 | `PythonREPLTool` on an agent driven by untrusted chat (prompt injection → code exec) | app.py:34 | Critical |
| 6 | Prompt injection — user input concatenated into the instruction prompt with tools attached | app.py:38-41 | High |
| 7 | Unpinned dependencies + no lockfile — non-reproducible, supply-chain swap risk (file-level anchor) | requirements.txt:- | High |
| 8 | MCP filesystem tool — raw `open(path).read()` on the tool argument: any client reads any file the process can (.env, keys) | mcp_server.py:10-12 | Critical |
| 9 | MCP exec tool — `subprocess.run(command, shell=True)` exposed as a tool: RCE by design | mcp_server.py:16-18 | Critical |
| 10 | MCP fetch tool echoes raw remote content into the model context — indirect prompt injection rides the tool result | mcp_server.py:24-26 | High |
| 11 | MCP SSE transport started with no auth layer — unauthenticated callers invoke every tool | mcp_server.py:43 | High |
| 12 | MCP connect endpoint grants server sessions by ID possession only — no per-server ACL at connect time; restricted MCP servers (stored OAuth credentials) reachable by any authenticated user (obot /mcp-connect pattern, CVE-2026-101084) | mcp_server.py:33-38 | High |

## Must NOT trigger (near-misses — `safe_app.py`)

- `load_file` on `.safetensors` (cannot execute code)
- fetch tool with host allowlist + redirects off
- Tool allowlist without shell/REPL entries
- User input as a message in the messages array (data, not instruction)
- `Anthropic(api_key=os.environ[...])` — key from env, not hardcoded
- `safe_mcp_server.py`: `_scoped()` root containment + truncation (:13-23), allowlisted argument-list command (:27-31), fetched content truncated + marked `[UNTRUSTED EXTERNAL CONTENT]` (:35-38), authenticated transport (:53), connect endpoint checks the caller's per-server ACL before opening any session (:42-48) — zero raw `open(path)`, `shell=True`, `urlopen`, bare `run(transport="sse")`, or ID-possession-only `MCP_SERVERS[server_id]` occurrences
