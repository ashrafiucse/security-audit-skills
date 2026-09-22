# SAFE counter-examples for llm-vuln-app. An audit must NOT report these.
import os

import requests
from safetensors.torch import load_file
from transformers import AutoModel


def load_model_safe():
    # SAFE (vs SEC-02/03): safetensors cannot execute code on load
    return load_file("models/first_party.safetensors")


def fetch_tool_safe(url: str) -> str:
    # SAFE (vs SEC-04): scheme+host allowlist, no redirects
    allowed = {"api.internal.example.com"}
    r = requests.get(url, allow_redirects=False, timeout=5)
    if r.url.split("//")[1].split("/")[0] not in allowed:
        raise ValueError("host not allowed")
    return r.text[:2000]


TOOL_ALLOWLIST = ("search_docs", "get_order_status")  # SAFE (vs SEC-05): no shell/REPL


def chat_safe(user_message: str, client) -> str:
    # SAFE (vs SEC-06): user input goes in the messages array as DATA,
    # never concatenated into the system/instruction text
    return client.messages.create(
        system="You are the shop assistant. Use only the provided tools.",
        messages=[{"role": "user", "content": user_message}],
        tools=[{"name": t} for t in TOOL_ALLOWLIST],
    )


def get_client():
    # SAFE (vs SEC-01): key from environment, never hardcoded
    from anthropic import Anthropic
    return Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
