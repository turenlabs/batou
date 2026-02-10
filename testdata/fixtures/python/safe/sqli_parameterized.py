# Safe: Parameterized SQL queries in Python
# Expected: No findings for GTSS-INJ-001

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)


@app.route("/search")
def search_users():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{name}%",))
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


@app.route("/orders")
def get_orders():
    user_id = request.args.get("user_id")
    status = request.args.get("status")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM orders WHERE user_id = ? AND status = ?",
        (user_id, status),
    )
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)
