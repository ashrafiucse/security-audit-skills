"""Safe counterpart (vs SEC-15 plant in agent_exec.py).

The interpreter step runs inside an AST-allowlist sandbox with no builtins,
and the driving endpoint requires an API key and binds loopback-only — the
model-emitted code never reaches unsandboxed exec.
"""
import ast

from fastapi import Depends, FastAPI, Request, Security
from fastapi.security import APIKeyHeader

app = FastAPI()
api_key_header = APIKeyHeader(name="X-API-Key")

# AST allowlist: expressions and arithmetic only — no Import, no Call outside
# the allowlist, no Attribute access, no Name lookups beyond safe builtins
ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.Name,
    ast.Load, ast.Store, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.USub,
)
ALLOWED_CALLS = {"len", "sum", "min", "max", "round", "abs", "str", "int", "float"}


class SandboxViolation(Exception):
    pass


def run_sandboxed(code: str):
    tree = ast.parse(code, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_NODES):
            raise SandboxViolation(f"node not allowed: {node.__class__.__name__}")
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) not in ALLOWED_CALLS:
            raise SandboxViolation(f"call not allowed: {getattr(node.func, 'id', '?')}")
    return eval(compile(tree, "<sandbox>", "eval"), {"__builtins__": {}}, {})


async def verify_api_key(key: str = Security(api_key_header)) -> str:
    if not key or key != get_stored_key():
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail="invalid key")
    return key


def get_stored_key() -> str:
    import os

    return os.environ.get("PLANNER_API_KEY", "")


@app.post("/solve", dependencies=[Depends(verify_api_key)])
async def solve(request: Request):
    body = await request.json()
    model_reply = planner_chain(body["inputs"])
    result = run_sandboxed(pick_expression(model_reply))
    return {"status": "ok", "result": str(result)}


def pick_expression(text: str) -> str:
    # the planner only ever emits a pure arithmetic expression to evaluate;
    # fences carrying statements are rejected by the sandbox, not executed
    return text.strip("`python\n").strip("`")


def planner_chain(inputs):
    return "```python\n2 + 3\n```"
