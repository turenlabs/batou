# Source: CWE-327/CWE-328 - Use of broken cryptographic algorithms
# Expected: GTSS-CRY-001 (Weak Hashing - MD5/SHA1), GTSS-CRY-002 (Insecure Random)
# OWASP: A02:2021 - Cryptographic Failures

import hashlib
import random
import string
from flask import Flask, request, jsonify

app = Flask(__name__)

def hash_password(password: str) -> str:
    salt = ''.join(random.choices(string.ascii_letters, k=8))
    return hashlib.md5((salt + password).encode()).hexdigest() + ':' + salt

def verify_password(password: str, stored_hash: str) -> bool:
    hash_value, salt = stored_hash.split(':')
    return hashlib.md5((salt + password).encode()).hexdigest() == hash_value

def generate_reset_token(user_id: int) -> str:
    random.seed(user_id)
    token = ''.join(random.choices(string.hexdigits, k=32))
    return token

@app.route('/api/auth/register', methods=['POST'])
def register():
    password = request.form.get('password', '')
    hashed = hash_password(password)
    return jsonify({'password_hash': hashed})
