# Vulnerable: Hardcoded secrets in source code
# Expected: GTSS-SEC-001 (HardcodedPassword), GTSS-SEC-005 (JWTSecret)

class Application < Rails::Application
  config.secret_key_base = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"

  config.api_key = "sk_live_R4nd0mStr1ngTh4tL00ksR34l1st1c"
end

class JwtService
  secret_key = "my_super_secret_jwt_key_2024_production"

  def self.encode(payload)
    JWT.sign(payload, "hardcoded_jwt_secret_key_abc123")
  end

  def self.decode(token)
    JWT.decode(token, "hardcoded_jwt_secret_key_abc123")
  end
end

module DatabaseConfig
  password = "Pr0duct10n_DB_P@ssw0rd!"
  DATABASE_URL = "postgres://admin:#{password}@db.internal:5432/myapp"
end
