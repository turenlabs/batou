import Foundation
import Security

// Weak PRNG — drand48 for token generation
func generateSessionToken() -> String {
    srand48(Int(Date().timeIntervalSince1970))
    let token = String(format: "%016x", Int(drand48() * Double(Int64.max)))
    return token
}

// Weak PRNG — rand() for nonce
func generateNonce() -> UInt32 {
    srand(UInt32(time(nil)))
    return UInt32(rand())
}

// Insecure TLS — blindly trust all certificates
class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // VULNERABLE: accepts any certificate, enables MITM
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}

// XXE — external entity resolution enabled
func parseUntrustedXML(data: Data) {
    let parser = XMLParser(data: data)
    parser.shouldResolveExternalEntities = true
    parser.parse()
}

// Unsafe memory — tainted allocation size
func processBuffer(sizeStr: String) {
    let size = Int(sizeStr) ?? 0
    let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
    ptr.initialize(repeating: 0, count: size)
    ptr.deallocate()
}

// Trust boundary — share sheet with sensitive data
func shareSensitiveData(token: String) {
    let vc = UIActivityViewController(activityItems: [token], applicationActivities: nil)
}

// Trust boundary — NSUserActivity handoff
func sendViaHandoff(secret: String) {
    let activity = NSUserActivity(activityType: "com.app.transfer")
    activity.userInfo = ["secret": secret]
    activity.becomeCurrent()
}

// Trust boundary — shared UserDefaults
func storeInSharedDefaults(apiKey: String) {
    let defaults = UserDefaults(suiteName: "group.com.app.shared")
    defaults?.set(apiKey, forKey: "api_key")
}
