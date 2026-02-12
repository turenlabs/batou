# PSB-A03-SQL-001: User search endpoint
# CWE: CWE-89
# Expected: GTSS-INJ-001, GTSS-INJ-002
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
    query = f"SELECT id, name, email FROM users WHERE name LIKE '%{q}%'"
    cursor.execute(query)
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)

if __name__ == "__main__":
    app.run()
