"""Safe counterpart: metadata API authenticated and loopback-bound. FAKE data only."""
import functools
import os

from flask import Flask, request, jsonify

app = Flask(__name__)

# SAFE (vs metadata_server.py): every route requires the engine's shared API
# key, and the server binds to loopback — the port is never published, so the
# control plane is reachable only from the serving host itself
def require_api_key(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        expected = os.environ.get("METADATA_API_KEY", "")
        got = request.headers.get("X-Api-Key", "")
        if not expected or not hmac_compare(got, expected):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapped


def hmac_compare(a, b):
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


@app.route("/metadata", methods=["GET", "POST", "DELETE"])
@require_api_key
def metadata():
    if request.method == "GET":
        return jsonify(METADATA)
    if request.method == "POST":
        METADATA.update(request.get_json())  # authenticated overwrite, engine hosts only
        return jsonify({"ok": True})
    METADATA.clear()
    return jsonify({"ok": True})


METADATA = {"tcp_data_port": 5002, "rpc_meta": "kv://10.0.0.5:50003", "segment_0": "kv://10.0.0.9:50010"}

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)  # loopback only; never published in compose/k8s
