# Fixture: intentionally vulnerable LLM app. FAKE data only.
# Covers: unsafe model deserialization, shell tool, prompt injection ->
# data exfil, hardcoded LLM keys, default tracing. Safe forms in
# safe_app.py. Expected findings: see expected-findings.md
import pickle

import requests
import torch
from anthropic import Anthropic
from langchain.agents import initialize_agent, load_tools
from langchain_experimental.tools import PythonREPLTool

client = Anthropic(api_key="sk-ant-api03-FakeKeyForEvalsDoNotUse0987654321abcdef")  # SEC-01

HF_TOKEN = "hf_FakeTokenForEvalsFixtures123"  # SEC-01b: HF token in source


def load_user_model(path):
    # SEC-02: pickled model from user upload executes on load
    with open(path, "rb") as f:
        return pickle.load(f)


def load_torch_model(path):
    # SEC-03: torch.load without weights_only — arbitrary code execution
    return torch.load(path)


def fetch_tool(url):
    # SEC-04: model-chosen URL, no allowlist — exfil + SSRF sink
    return requests.get(url, timeout=5).text


tools = load_tools(["requests_all"], llm=None) + [PythonREPLTool()]  # SEC-05: REPL tool on untrusted chat
agent = initialize_agent(tools, llm=None, agent="zero-shot-react-description")


def chat(user_message: str) -> str:
    # SEC-06: user input concatenated into the system/instruction prompt
    prompt = f"You are the shop assistant. Help the user: {user_message}"
    return agent.run(prompt)
