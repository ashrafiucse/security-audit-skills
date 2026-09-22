# Fixture: intentionally vulnerable Python/Flask app — part 2. FAKE data only.
# Covers XXE (lxml + stdlib) and open redirect. Safe counter-examples live in
# safe_counterexamples.py. Expected findings: see expected-findings.md
import xml.etree.ElementTree as ET

from flask import Flask, redirect, request
from lxml import etree

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_xml():
    # SEC-01: lxml default parser resolves entities (incl. external file://) — XXE read/SSRF
    tree = etree.fromstring(request.get_data())
    return etree.tostring(tree)


@app.route("/feed", methods=["POST"])
def feed():
    # SEC-02: stdlib XML parser on user input — internal entity expansion (billion laughs) DoS
    root = ET.fromstring(request.get_data())
    return root.tag or "ok"


@app.route("/logout")
def logout():
    # SEC-03: open redirect — attacker-controlled target from query param
    return redirect(request.args.get("next", "/"))
