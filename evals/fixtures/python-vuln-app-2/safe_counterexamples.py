# SAFE counter-examples for python-vuln-app-2. An audit must NOT report these.
# See expected-findings.md.
from urllib.parse import urlparse

import defusedxml.ElementTree as SafeET
from flask import Flask, redirect, request

app = Flask(__name__)

ALLOWED_REDIRECTS = {"/dashboard", "/"}


def import_safe(data: bytes):
    # SAFE (vs SEC-01): defusedxml blocks DTDs and entity expansion
    return SafeET.fromstring(data)


@app.route("/logout-safe")
def logout_safe():
    # SAFE (vs SEC-03): exact allowlist; absolute URLs and "//evil.com" rejected
    nxt = request.args.get("next", "/dashboard")
    if nxt not in ALLOWED_REDIRECTS:
        nxt = "/dashboard"
    return redirect(nxt)


def parse_url_checked(raw: str):
    # SAFE helper: reject absolute/protocol-relative redirects before joining
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc or raw.startswith("//"):
        raise ValueError("absolute redirect")
    return parsed.path
