import Foundation
import Security

// VULNERABLE: Keychain item accessible when device is locked
func storeTokenInsecure(token: String) {
    let tokenData = token.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleAlways,
        kSecAttrAccount as String: "authToken",
        kSecValueData as String: tokenData
    ]
    SecItemAdd(query as CFDictionary, nil)
}

// VULNERABLE: kSecAttrAccessibleAlwaysThisDeviceOnly
func storeCredentialInsecure(credential: String) {
    let data = credential.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleAlwaysThisDeviceOnly,
        kSecAttrAccount as String: "credential",
        kSecValueData as String: data
    ]
    SecItemAdd(query as CFDictionary, nil)
}
