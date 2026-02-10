# Safe: Strong cryptography with BCrypt and SecureRandom
# Expected: No findings for GTSS-CRY-001 or GTSS-CRY-010

require 'bcrypt'
require 'securerandom'

class AuthService
  BCRYPT_COST = 12

  def hash_password(password)
    BCrypt::Password.create(password, cost: BCRYPT_COST)
  end

  def verify_password(password, stored_hash)
    BCrypt::Password.new(stored_hash) == password
  end

  def generate_token
    SecureRandom.hex(32)
  end

  def generate_session_id
    SecureRandom.uuid
  end

  def generate_api_key
    SecureRandom.urlsafe_base64(48)
  end

  def generate_otp
    SecureRandom.random_number(1000000).to_s.rjust(6, '0')
  end
end
