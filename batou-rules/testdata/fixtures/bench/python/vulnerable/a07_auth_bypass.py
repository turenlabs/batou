# Source: CWE-287 - Improper authentication in JWT handling
# Expected: BATOU-AUTH-001 (Hardcoded Credentials), BATOU-SEC-005 (JWT Secret)
# OWASP: A07:2021 - Identification and Authentication Failures

import jwt
import time
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = "my-secret-key-2024"

@app.route('/api/auth/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == 'admin' and password == 'admin123':
        token = jwt.encode(
            {'sub': username, 'exp': time.time() + 86400},
            JWT_SECRET,
            algorithm='HS256'
        )
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/verify')
def verify():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256', 'none'])
        return jsonify({'user': decoded['sub']})
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 403
