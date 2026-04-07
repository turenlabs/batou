import Foundation
import Security

// VULNERABLE: Insecure URLSession that trusts all certificates
class InsecureNetworkManager: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // GTSS-SWIFT-001: Accepts all server certificates without validation
        let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
        completionHandler(.useCredential, credential)
    }

    func fetchData(from url: URL) {
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: url) { data, response, error in
            // process data
        }
        task.resume()
    }
}

// VULNERABLE: Insecure Keychain storage
func storeTokenInsecurely(token: String) {
    let tokenData = token.data(using: .utf8)!
    // GTSS-SWIFT-003: kSecAttrAccessibleAlways makes data accessible when device is locked
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleAlways,
        kSecAttrAccount as String: "userToken",
        kSecValueData as String: tokenData
    ]
    SecItemAdd(query as CFDictionary, nil)
}

// VULNERABLE: Hardcoded secrets
class APIConfiguration {
    // GTSS-SWIFT-005: Hardcoded API key
    let apiKey = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
    let secretToken = "ghp_1234567890abcdefghijklmnopqrstuvwx"
    let databasePassword = "production_db_password_2024!"

    // GTSS-SWIFT-005: AWS access key
    let awsKey = "AKIAJ4MBRZBKQW9HWCQA"
}
