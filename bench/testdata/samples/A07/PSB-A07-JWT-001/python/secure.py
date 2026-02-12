# PSB-A07-JWT-001: JWT authentication middleware
# CWE: CWE-345, CWE-347
# Expected: (none - secure)
from flask import Flask, request, jsonify, g
import jwt
import os
import datetime
from functools import wraps

app = Flask(__name__)
SECRET_KEY = os.environ["JWT_SECRET"]

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "missing authorization header"}), 401

        token = header[7:]
        try:
            decoded = jwt.decode(
                token, SECRET_KEY, algorithms=["HS256"],
                options={"require": ["exp", "sub"]},
            )
            g.user = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    token = jwt.encode(
        {"sub": data["username"], "role": "user",
         "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        SECRET_KEY, algorithm="HS256",
    )
    return jsonify({"token": token})

@app.route("/api/profile")
@auth_required
def profile():
    return jsonify({"user": g.user})

if __name__ == "__main__":
    app.run()
