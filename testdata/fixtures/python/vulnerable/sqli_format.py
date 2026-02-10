# Vulnerable: SQL injection via % string formatting
# Expected: GTSS-INJ-001 (SQL Injection)

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/accounts")
def get_account():
    account_id = request.args["id"]
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE id = '%s'" % account_id)
    row = cursor.fetchone()
    conn.close()
    return jsonify(row)


@app.route("/orders")
def get_orders():
    user_id = request.form.get("user_id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM orders WHERE user_id = %s" % user_id
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)


@app.route("/products")
def search_products():
    keyword = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE '%%{}%%'".format(keyword)
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)
