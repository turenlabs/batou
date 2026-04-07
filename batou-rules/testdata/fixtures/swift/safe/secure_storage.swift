import Foundation
import Security

// SAFE: Keychain with proper accessibility
func storeTokenSecurely(token: String) {
    let tokenData = token.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAttrAccount as String: "authToken",
        kSecValueData as String: tokenData
    ]
    SecItemAdd(query as CFDictionary, nil)
}

// SAFE: Secrets loaded from environment
class Configuration {
    var apiKey: String {
        return ProcessInfo.processInfo.environment["API_KEY"] ?? ""
    }
}

// SAFE: UserDefaults for non-sensitive preferences
func savePreferences(theme: String) {
    UserDefaults.standard.set(theme, forKey: "preferredTheme")
}

// SAFE: Secure random
func generateNonce() -> Data {
    var bytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    return Data(bytes)
}
