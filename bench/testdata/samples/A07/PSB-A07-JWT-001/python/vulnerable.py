# PSB-A07-JWT-001: JWT authentication middleware
# CWE: CWE-345, CWE-347
# Expected: GTSS-SEC-001, GTSS-AUTH-003
from flask import Flask, request, jsonify, g
import jwt
from functools import wraps

app = Flask(__name__)
SECRET_KEY = "supersecretkey"

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header:
            return jsonify({"error": "missing authorization header"}), 401

        token = header.replace("Bearer ", "")
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            g.user = decoded
        except Exception:
            return jsonify({"error": "invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    token = jwt.encode({"sub": data["username"], "role": "user"}, SECRET_KEY)
    return jsonify({"token": token})

@app.route("/api/profile")
@auth_required
def profile():
    return jsonify({"user": g.user})

if __name__ == "__main__":
    app.run()
