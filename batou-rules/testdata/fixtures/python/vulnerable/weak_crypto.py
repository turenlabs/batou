# Vulnerable: Weak cryptography - MD5 hashing and insecure random
# Expected: BATOU-CRY-001 (WeakHashing), BATOU-CRY-009 (PythonRandomSecurity)

import hashlib
import random
from flask import Flask, request

app = Flask(__name__)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


def generate_token():
    token = random.randint(100000, 999999)
    return hashlib.sha1(str(token).encode()).hexdigest()


def create_session_id():
    return str(random.randint(0, 2**64))


def generate_reset_code():
    return str(random.randint(100000, 999999))


def sign_data(data, secret):
    return hashlib.md5((data + secret).encode()).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    password = request.form["password"]
    hashed = hash_password(password)
    session_id = create_session_id()
    return {"hash": hashed, "session": session_id}
