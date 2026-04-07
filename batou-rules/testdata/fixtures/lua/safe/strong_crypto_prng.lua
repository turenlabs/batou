-- Safe: strong cryptographic patterns in Lua

local resty_random = require "resty.random"
local resty_sha256 = require "resty.sha256"
local resty_sha512 = require "resty.sha512"
local resty_hmac = require "resty.hmac"
local str = require "resty.string"

-- CSPRNG for session token generation
function generate_session_token()
    local bytes = resty_random.bytes(32)
    return str.to_hex(bytes)
end

-- SHA-256 for password hashing (with salt)
function hash_password(password, salt)
    local sha256 = resty_sha256:new()
    sha256:update(salt .. password)
    local digest = sha256:final()
    return str.to_hex(digest)
end

-- SHA-512 for API key derivation
function derive_api_key(secret, context)
    local sha512 = resty_sha512:new()
    sha512:update(context .. ":" .. secret)
    local digest = sha512:final()
    return str.to_hex(digest)
end

-- HMAC for integrity verification
function verify_integrity(data, key)
    local hmac = resty_hmac:new(key, resty_hmac.ALGOS.SHA256)
    hmac:update(data)
    local mac = hmac:final()
    return str.to_hex(mac)
end

-- CSPRNG for password reset token
function generate_reset_token()
    local bytes = resty_random.bytes(24)
    return ngx.encode_base64(bytes)
end
