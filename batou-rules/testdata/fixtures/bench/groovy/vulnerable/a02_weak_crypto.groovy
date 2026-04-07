// Source: CWE-327 - Use of weak MD5 hash via MessageDigest in Groovy
// Expected: BATOU-CRY
// OWASP: A02:2021 - Cryptographic Failures

import java.security.MessageDigest

def hashPassword(String password) {
    def md = MessageDigest.getInstance("MD5")
    def digest = md.digest(password.getBytes("UTF-8"))
    return digest.collect { String.format("%02x", it) }.join()
}

println hashPassword("admin123")
