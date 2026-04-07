// Source: CWE-327 - Use of weak crypto via MessageDigest.getInstance("MD5") in Kotlin
// Expected: BATOU-CRY
// OWASP: A02:2021 - Cryptographic Failures

import java.security.MessageDigest

fun hashPassword(password: String): String {
    val md = MessageDigest.getInstance("MD5")
    val digest = md.digest(password.toByteArray())
    return digest.joinToString("") { "%02x".format(it) }
}

fun verifySHA1(input: String): String {
    val sha = MessageDigest.getInstance("SHA-1")
    val digest = sha.digest(input.toByteArray())
    return digest.joinToString("") { "%02x".format(it) }
}

fun main() {
    println("MD5: ${hashPassword("admin123")}")
    println("SHA1: ${verifySHA1("test")}")
}
