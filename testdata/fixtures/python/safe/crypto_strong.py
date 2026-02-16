# Safe: Strong cryptography with bcrypt and secrets module
# Expected: No findings for BATOU-CRY-001 or BATOU-CRY-009

import bcrypt
import secrets
import hashlib


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())


def generate_token() -> str:
    return secrets.token_hex(32)


def generate_session_id() -> str:
    return secrets.token_urlsafe(48)


def generate_api_key() -> str:
    return secrets.token_urlsafe(64)


def generate_otp() -> str:
    return str(secrets.randbelow(1000000)).zfill(6)


def generate_csrf_token() -> str:
    return secrets.token_hex(16)


def hash_for_integrity(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
