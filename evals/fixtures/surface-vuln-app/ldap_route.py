"""LDAP auth routes (enterprise directory). Flask + ldap3."""
from flask import request, jsonify
from ldap3 import Server, Connection, ANONYMOUS

LDAP_HOST = "ldap.corp.example-fake.com"
BASE_DN = "ou=people,dc=corp,dc=example-fake,dc=com"


def _connect(user_dn, password):
    server = Server(LDAP_HOST)
    return Connection(server, user=user_dn, password=password)


def login_concat_dn():
    # DN built by string concatenation -> DN injection (rebind as other principal)
    uid = request.form["uid"]
    dn = "uid=" + uid + "," + BASE_DN
    conn = _connect(dn, request.form["password"])
    if not conn.bind():
        return jsonify({"error": "bad credentials"}), 401
    return jsonify({"uid": uid})


def login_anonymous():
    # Anonymous bind accepted as an auth method
    server = Server(LDAP_HOST)
    conn = Connection(server, user=None, password=None, authentication=ANONYMOUS)
    conn.bind()
    return jsonify({"result": conn.extend.standard.who_am_i()})


def search_filter_format():
    # Filter built with f-string -> LDAP filter injection (wildcard/boolean)
    name = request.args["name"]
    conn = _connect("uid=svc-reader," + BASE_DN, "FakeReaderPass4Eval")
    conn.search(BASE_DN, f"(sAMAccountName={name})")
    return jsonify({"entries": len(conn.entries)})
