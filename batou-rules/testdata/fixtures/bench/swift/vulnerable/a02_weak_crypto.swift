// Source: CWE-327 - Use of weak MD5 hash in Swift
// Expected: BATOU-SWIFT
// OWASP: A02:2021 - Cryptographic Failures

import Foundation
import CommonCrypto

func md5Hash(_ input: String) -> String {
    let data = Data(input.utf8)
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    data.withUnsafeBytes { bytes in
        _ = CC_MD5(bytes.baseAddress, CC_LONG(data.count), &digest)
    }
    return digest.map { String(format: "%02x", $0) }.joined()
}

let password = "user_password"
let hashed = md5Hash(password)
print("MD5: \(hashed)")
