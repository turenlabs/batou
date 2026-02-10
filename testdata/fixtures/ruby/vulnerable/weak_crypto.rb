# Vulnerable: Weak cryptographic hashing (MD5, SHA1) for passwords
# Expected: GTSS-CRY-001 (WeakHashing), GTSS-CRY-010 (WeakPRNG)

require 'digest'

class AuthService
  def hash_password(password)
    Digest::MD5.hexdigest(password)
  end

  def verify_password(password, stored_hash)
    Digest::MD5.hexdigest(password) == stored_hash
  end

  def generate_token
    token = rand(999999).to_s
    Digest::SHA1.hexdigest(token)
  end

  def create_session_id
    rand(100000000).to_s(16)
  end

  def sign_data(data, secret)
    Digest::MD5.hexdigest("#{data}#{secret}")
  end
end
