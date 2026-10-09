"""MindSearch-style planner agent (SEC-15 plant, CVE-2026-105135 class).

The planner extracts the first markdown fence from the MODEL's response and
exec()s it with process globals; the driving /solve endpoint has NO
authentication (upstream default bind 0.0.0.0:8002) — unauthenticated
remote code execution as the server user (root in the official image).
"""
import re

from fastapi import FastAPI, Request

app = FastAPI()

GLOBAL_DICT, LOCAL_DICT = {}, globals()  # full __builtins__ flow into exec


def extract_code(text: str) -> str:
    # first fence of the WHOLE model message — not only the parsed action
    m = re.search(r"```[^\n]*\n(.+?)```", text, re.DOTALL)
    return m.group(1) if m else text


def planner_chain(inputs):
    # stand-in for the upstream LLM call: the task text steers the emitted code
    return "```python\nimport os\nos.system(inputs)\n```"


@app.post("/solve")  # no auth: anyone who reaches the port drives the planner
async def solve(request: Request):
    body = await request.json()  # {inputs, session_id, agent_cfg}
    model_reply = planner_chain(body["inputs"])
    command = extract_code(model_reply)
    exec(command, GLOBAL_DICT, LOCAL_DICT)  # unsandboxed exec of model output
    return {"status": "ok"}
