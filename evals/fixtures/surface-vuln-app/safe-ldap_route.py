"""LDAP auth — safe shapes (escape-then-bind, escaped filter terms)."""
from flask import request, jsonify
from ldap3 import Server, Connection
from ldap3.utils.conv import escape_dn_chars, escape_filter_chars

LDAP_HOST = "ldap.corp.example-fake.com"
BASE_DN = "ou=people,dc=corp,dc=example-fake,dc=com"


def _connect(user_dn, password):
    server = Server(LDAP_HOST)
    return Connection(server, user=user_dn, password=password)


def login_safe():
    uid = request.form["uid"]
    dn = "uid=" + escape_dn_chars(uid) + "," + BASE_DN
    conn = _connect(dn, request.form["password"])
    if not conn.bind():
        return jsonify({"error": "bad credentials"}), 401
    return jsonify({"uid": uid})


def search_filter_safe():
    name = request.args["name"]
    conn = _connect("uid=svc-reader," + BASE_DN, "FakeReaderPass4Eval")
    conn.search(BASE_DN, f"(sAMAccountName={escape_filter_chars(name)})")
    return jsonify({"entries": len(conn.entries)})
