import Foundation
import Security
import CryptoKit

// Secure random — SecRandomCopyBytes
func generateSecureToken() -> Data {
    var bytes = [UInt8](repeating: 0, count: 32)
    SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    return Data(bytes)
}

// Secure random — SystemRandomNumberGenerator
func generateSecureNonce() -> UInt64 {
    return UInt64.random(in: 0...UInt64.max)
}

// Proper TLS — evaluate trust with error checking
class SecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

// Safe XML parsing — external entities disabled (default)
func parseXMLSafely(data: Data) {
    let parser = XMLParser(data: data)
    parser.shouldResolveExternalEntities = false
    parser.parse()
}

// Safe memory — bounds checked
func processBufferSafe(size: Int) {
    precondition(size < 1024 * 1024)
    let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
    ptr.initialize(repeating: 0, count: size)
    ptr.deallocate()
}

// Safe sharing — excluded activity types
func shareWithRestrictions(data: String) {
    let vc = UIActivityViewController(activityItems: [data], applicationActivities: nil)
    vc.excludedActivityTypes = [.airDrop, .copyToPasteboard, .mail]
}

// Safe pasteboard — local only
func copyToLocalPasteboard(text: String) {
    UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: text]],
                                   options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
}
