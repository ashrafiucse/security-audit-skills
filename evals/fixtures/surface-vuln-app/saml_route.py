# Fixture: misc leak/privilege surfaces. FAKE data only.
# Covers: SAML classic bugs, K8s RBAC escalation verbs, serverless IAM +
# authorizer gaps, dev-artifact leaks.
# Expected findings: see expected-findings.md
from flask import Flask, request

from onelogin.saml2.auth import OneLogin_Saml2_Auth

app = Flask(__name__)

SAML_SETTINGS = {
    "strict": False,  # SEC-01: non-strict mode disables most validations
    "security": {
        "wantResponseSigned": False,   # SEC-02: response signature not required
        "wantAssertionsSigned": False,  # SEC-02b: assertion signature not required
        "wantNameId": True,
        "requestedAuthnContext": False,
    },
    "idp": {"entityId": "https://idp.example-fake.com/saml/metadata"},
    # SEC-03: ACS URL not pinned; audience not validated (missing)
}


@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    req = {"POST": request.form, "GET": request.args}
    auth = OneLogin_Saml2_Auth(req, SAML_SETTINGS)
    auth.process_response()
    if not auth.get_errors():
        # SEC-04: NameID consumed raw without format check (comment-injection class)
        name_id = auth.get_nameid()
        return f"logged in as {name_id}"
    return "saml error", 400
