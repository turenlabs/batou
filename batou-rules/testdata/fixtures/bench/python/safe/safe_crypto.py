import hashlib
import hmac
import secrets
import os
from typing import Tuple

# SAFE: secrets module for token generation (not random module)
def generate_api_token() -> str:
    return secrets.token_hex(32)


# SAFE: secrets.token_urlsafe for CSRF tokens
def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


# SAFE: hashlib.pbkdf2_hmac for password hashing (not MD5/SHA1 alone)
def hash_password(password: str) -> Tuple[bytes, bytes]:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt, key


# SAFE: hmac.compare_digest for timing-safe comparison
def verify_password(password: str, salt: bytes, stored_key: bytes) -> bool:
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return hmac.compare_digest(candidate, stored_key)


# SAFE: SHA-256 for content integrity (non-security context, just checksums)
def file_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# SAFE: HMAC-SHA256 for message authentication
def sign_message(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()
