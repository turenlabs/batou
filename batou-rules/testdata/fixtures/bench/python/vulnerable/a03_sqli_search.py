# Source: OWASP WebGoat - SQL injection in search functionality
# Expected: BATOU-INJ-001 (SQL Injection via string formatting)
# OWASP: A03:2021 - Injection (SQL Injection)

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = '/var/lib/app/products.db'

@app.route('/api/products/search')
def search_products():
    query = request.args.get('q', '')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%' OR description LIKE '%" + query + "%'"
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.close()
    return jsonify([dict(zip(['id', 'name', 'price', 'description'], row)) for row in results])

@app.route('/api/products/<int:product_id>')
def get_product(product_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE id = {product_id}")
    product = cursor.fetchone()
    conn.close()
    if product:
        return jsonify(dict(zip(['id', 'name', 'price', 'description'], product)))
    return jsonify({'error': 'Not found'}), 404
