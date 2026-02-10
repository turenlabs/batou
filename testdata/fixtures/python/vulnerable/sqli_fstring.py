# Vulnerable: SQL injection via f-string in Flask route
# Expected: GTSS-INJ-001 (SQL Injection)

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/users")
def get_user():
    user_id = request.args['id']
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)


@app.route("/search")
def search_users():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)
