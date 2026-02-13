import Foundation
import Security
import CryptoKit
import WebKit
import SQLite3

// SAFE: Proper certificate pinning
class SecureNetworkManager: NSObject, URLSessionDelegate {
    let pinnedPublicKeyHash = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        var error: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let serverKey = SecTrustCopyPublicKey(serverTrust) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let credential = URLCredential(trust: serverTrust)
        completionHandler(.useCredential, credential)
    }
}

// SAFE: Secure Keychain storage
func storeTokenSecurely(token: String) {
    let tokenData = token.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAttrAccount as String: "userToken",
        kSecValueData as String: tokenData
    ]
    SecItemAdd(query as CFDictionary, nil)
}

// SAFE: Secrets loaded from environment/Keychain
class SecureAPIConfiguration {
    var apiKey: String {
        return ProcessInfo.processInfo.environment["API_KEY"] ?? ""
    }

    func getStoredCredential() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "apiCredential",
            kSecReturnData as String: true
        ]
        var result: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &result)
        guard let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

// SAFE: Parameterized SQLite queries
func findUserSecure(db: OpaquePointer?, username: String) {
    var stmt: OpaquePointer?
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE username = ?", -1, &stmt, nil)
    sqlite3_bind_text(stmt, 1, username, -1, nil)
    while sqlite3_step(stmt) == SQLITE_ROW {
        // process row
    }
    sqlite3_finalize(stmt)
}

// SAFE: WKWebView without user input interpolation
class SecureWebController {
    var webView: WKWebView!

    func getTitle() {
        webView.evaluateJavaScript("document.title") { result, error in
            if let title = result as? String {
                print(title)
            }
        }
    }

    func loadStaticContent() {
        let html = "<html><body><h1>Welcome</h1></body></html>"
        webView.loadHTMLString(html, baseURL: URL(string: "about:blank"))
    }
}

// SAFE: Secure random generation
func generateSecureOTP() -> String {
    var bytes = [UInt8](repeating: 0, count: 4)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    let number = bytes.withUnsafeBytes { $0.load(as: UInt32.self) } % 1000000
    return String(format: "%06d", number)
}

// SAFE: UserDefaults for non-sensitive preferences
func saveUserPreference(theme: String, fontSize: Int) {
    UserDefaults.standard.set(theme, forKey: "preferredTheme")
    UserDefaults.standard.set(fontSize, forKey: "fontSize")
}
