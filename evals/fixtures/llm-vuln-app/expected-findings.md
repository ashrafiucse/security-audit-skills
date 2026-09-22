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

## Must NOT trigger (near-misses — `safe_app.py`)

- `load_file` on `.safetensors` (cannot execute code)
- fetch tool with host allowlist + redirects off
- Tool allowlist without shell/REPL entries
- User input as a message in the messages array (data, not instruction)
- `Anthropic(api_key=os.environ[...])` — key from env, not hardcoded
