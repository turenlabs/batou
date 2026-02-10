# Vulnerable: Hardcoded secrets in Python source code
# Expected: GTSS-SEC-001 (HardcodedPassword), GTSS-SEC-005 (JWTSecret)

import jwt

SECRET_KEY = "my_super_secret_key_do_not_share_12345"

API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"

DATABASE_PASSWORD = "Pr0duct10n_DB_P@ssw0rd!"


class Config:
    secret_key = "flask_secret_a1b2c3d4e5f6g7h8i9j0"
    jwt_secret = "jwt_signing_key_xyz789"
    api_secret = "api_s3cret_k3y_f0r_pr0d"


def get_db_connection():
    password = "db_admin_password_2024!"
    return f"postgresql://admin:{password}@db.production.internal:5432/myapp"


def create_jwt(user_id):
    payload = {"user_id": user_id, "exp": 3600}
    return jwt.encode(payload, "hardcoded_jwt_secret_key_abc123", algorithm="HS256")


def decode_jwt(token):
    return jwt.decode(token, "hardcoded_jwt_secret_key_abc123", algorithms=["HS256"])
