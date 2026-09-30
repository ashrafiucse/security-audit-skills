"""MCP server surface (fixture: intentionally vulnerable). FAKE data only."""
import subprocess

from mcp.server import Server

server = Server("docs-assistant")


# SEC: filesystem tool — raw open() on the tool argument: any client reads any file
@server.tool("read_file")
async def read_file(path: str) -> str:
    return open(path).read()


# SEC: exec tool — RCE by design, string command through a shell
@server.tool("run_command")
async def run_command(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout.decode()


# SEC: web-fetch tool echoes raw remote content into the model context
@server.tool("fetch_docs")
async def fetch_docs(url: str) -> str:
    import urllib.request
    return urllib.request.urlopen(url).read().decode()


MCP_SERVERS = registry.servers()  # includes restricted servers with stored OAuth creds


# SEC: connect endpoint — server-ID possession is treated as authorization
# (obot /mcp-connect pattern, CVE-2026-101084): any authenticated user gets a
# live session on restricted MCP servers carrying stored OAuth credentials
@server.tool("mcp_connect")
async def mcp_connect(server_id: str) -> str:
    target = MCP_SERVERS[server_id]
    return target.open_session()      # no per-server ACL check at connect time


def main():
    # SEC: network transport with no auth layer
    server.run(transport="sse")
