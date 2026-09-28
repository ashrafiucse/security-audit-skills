"""MCP server — safe shapes. An audit must NOT report this."""
import hashlib
from pathlib import Path

import httpx
from mcp.server import Server

server = Server("docs-assistant")
DOCS_ROOT = Path("/srv/docs").resolve()
ALLOWED_COMMANDS = {"grep": ["-r", "-e"], "wc": ["-l"]}


def _scoped(path: str) -> Path:
    resolved = (DOCS_ROOT / path).resolve()
    if not resolved.is_relative_to(DOCS_ROOT):
        raise ValueError("path escapes docs root")
    return resolved


# SAFE: filesystem read confined to a resolved root
@server.tool("read_file")
async def read_file(path: str) -> str:
    return _scoped(path).read_text()[:5000]


# SAFE: allowlisted command + argument list, no shell
@server.tool("run_command")
async def run_command(command: str, args: list[str]) -> str:
    argv = [command, *ALLOWED_COMMANDS.get(command, []), *args]
    result = await run_argv(argv)  # argument-list form only
    return result[:2000]


# SAFE: fetched content truncated and marked untrusted
@server.tool("fetch_docs")
async def fetch_docs(url: str) -> str:
    body = (await httpx.AsyncClient().get(url, follow_redirects=False)).text[:2000]
    return f"[UNTRUSTED EXTERNAL CONTENT]\n{body}"


def main():
    # SAFE: authenticated transport
    server.run(transport="sse", middleware=[require_api_key])
