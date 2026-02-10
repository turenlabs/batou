# Vulnerable: Unsafe deserialization via pickle.loads on user input
# Expected: Taint sink match for py.pickle.loads (CWE-502)

import pickle
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/restore-session", methods=["POST"])
def restore_session():
    cookie_data = request.cookies.get("session_data")
    decoded = base64.b64decode(cookie_data)
    session_obj = pickle.loads(decoded)
    return jsonify(session_obj)


@app.route("/import", methods=["POST"])
def import_data():
    raw_data = request.data
    imported = pickle.loads(raw_data)
    return jsonify({"status": "imported", "count": len(imported)})


@app.route("/deserialize", methods=["POST"])
def deserialize():
    blob = request.form.get("blob")
    decoded = base64.b64decode(blob)
    obj = pickle.loads(decoded)
    return jsonify(obj)
