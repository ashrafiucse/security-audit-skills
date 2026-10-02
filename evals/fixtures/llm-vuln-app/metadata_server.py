"""Mooncake-style HTTP metadata server (fixture: intentionally vulnerable). FAKE data only."""
from flask import Flask, request, jsonify

app = Flask(__name__)

# SEC: KV-transfer metadata readable/writable/deletable by anyone who can reach
# the port — segment descriptors (tcp_data_port, rpc_meta) can be poisoned to
# redirect cache transfers to attacker listeners (Mooncake CVE-2026-103765:
# http_metadata_server /metadata had no authentication on any method)
@app.route("/metadata", methods=["GET", "POST", "DELETE"])
def metadata():
    if request.method == "GET":
        return jsonify(METADATA)
    if request.method == "POST":
        METADATA.update(request.get_json(force=True))  # unauthenticated overwrite
        return jsonify({"ok": True})
    METADATA.clear()  # unauthenticated delete
    return jsonify({"ok": True})


METADATA = {"tcp_data_port": 5002, "rpc_meta": "kv://10.0.0.5:50003", "segment_0": "kv://10.0.0.9:50010"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)  # all interfaces, no auth layer
