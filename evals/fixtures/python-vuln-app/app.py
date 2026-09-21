# Fixture: intentionally vulnerable Python/Flask app. FAKE data only.
import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

ADMIN_TOKEN = "hf_FakeTokenForEvalFixtures123"          # SEC-01: hardcoded token (fake, off-format)
DB_PASSWORD = "changeme-prod-2024"                      # SEC-01b

# SEC-02: debug mode left on (Werkzeug debugger = RCE)
app.config["DEBUG"] = True


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("app.db")
    # SEC-03: SQL injection via f-string
    row = conn.execute(f"SELECT * FROM users WHERE name = '{username}'").fetchone()
    if row and row[2] == password:  # SEC-04: plaintext password comparison
        return "welcome"
    return "nope", 401


@app.route("/import", methods=["POST"])
def import_data():
    # SEC-05: insecure deserialization
    data = pickle.loads(request.get_data())
    return str(data)


@app.route("/render", methods=["POST"])
def render():
    # SEC-06: unsafe yaml load
    cfg = yaml.load(request.get_data(), Loader=yaml.Loader)
    return str(cfg)


@app.route("/backup", methods=["POST"])
def backup():
    # SEC-07: shell injection
    subprocess.call("tar czf /tmp/backup.tar.gz " + request.form["path"], shell=True)
    return "ok"


@app.route("/file")
def get_file():
    # SEC-08: path traversal
    return open(request.args.get("name")).read()


@app.route("/health")
def health():
    # SEC-09: logs sensitive data
    print(f"auth header: {request.headers.get('Authorization')}, token: {ADMIN_TOKEN}")
    return "ok"
