# PSB-A03-SQL-001: User search endpoint
# CWE: CWE-89
# Expected: (none - secure)
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/api/users/search")
def search_users():
    q = request.args.get("q", "")
    if not q:
        return jsonify({"error": "query parameter 'q' is required"}), 400

    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, email FROM users WHERE name LIKE ?",
        (f"%{q}%",),
    )
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)

if __name__ == "__main__":
    app.run()
