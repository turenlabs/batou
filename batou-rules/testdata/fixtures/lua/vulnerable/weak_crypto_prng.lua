-- Vulnerable: weak PRNG and hashing patterns in Lua

local resty_md5 = require "resty.md5"
local resty_sha1 = require "resty.sha1"
local str = require "resty.string"

-- CWE-330: Weak PRNG for session token generation
function generate_session_token()
    math.randomseed(os.time())
    local token = ""
    for i = 1, 32 do
        token = token .. string.format("%02x", math.random(0, 255))
    end
    return token
end

-- CWE-330: Weak PRNG for CSRF token
function generate_csrf_token()
    math.randomseed(os.clock())
    return tostring(math.random(100000, 999999))
end

-- CWE-328: Weak MD5 hash for password storage
function hash_password(password)
    local md5 = resty_md5:new()
    md5:update(password)
    local digest = md5:final()
    return str.to_hex(digest)
end

-- CWE-328: Weak SHA-1 hash for API key derivation
function derive_api_key(secret)
    local sha1 = resty_sha1:new()
    sha1:update(secret)
    local digest = sha1:final()
    return str.to_hex(digest)
end

-- CWE-328: Weak SHA-1 via ngx builtin
function verify_integrity(data)
    local hash = ngx.sha1_bin(data)
    return ngx.encode_base64(hash)
end

-- CWE-330: Weak PRNG for password reset token
function generate_reset_token(user_id)
    math.randomseed(os.time() + user_id)
    local token = ""
    for i = 1, 16 do
        token = token .. string.char(math.random(65, 90))
    end
    return token
end
