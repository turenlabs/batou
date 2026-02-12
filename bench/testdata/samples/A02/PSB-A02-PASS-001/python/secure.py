# PSB-A02-PASS-001: Password storage/registration
# CWE: CWE-916, CWE-328
# Expected: (none - secure)
from flask import Flask, request, jsonify
import bcrypt
import sqlite3
import re

app = Flask(__name__)

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return jsonify({"error": "invalid email"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

    conn = sqlite3.connect("app.db")
    conn.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, hashed),
    )
    conn.commit()
    conn.close()

    return jsonify({"id": 1, "username": username, "email": email}), 201

if __name__ == "__main__":
    app.run()
