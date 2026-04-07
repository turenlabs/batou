import Foundation
import SQLite3
import WebKit

// VULNERABLE: SQL injection via string interpolation
func findUser(db: OpaquePointer?, username: String) {
    // GTSS-SWIFT-007: String interpolation in SQL query
    let query = "SELECT * FROM users WHERE username = '\(username)'"
    sqlite3_exec(db, query, nil, nil, nil)
}

func deleteUser(db: OpaquePointer?, userId: String) {
    // GTSS-SWIFT-007: Another SQL injection vector
    let deleteQuery = "DELETE FROM users WHERE id = \(userId)"
    sqlite3_exec(db, deleteQuery, nil, nil, nil)
}

// VULNERABLE: WKWebView JavaScript injection
class VulnerableWebController {
    var webView: WKWebView!

    // GTSS-SWIFT-008: evaluateJavaScript with string interpolation
    func updateUserName(name: String) {
        webView.evaluateJavaScript("document.getElementById('name').innerText = '\(name)'")
    }

    // GTSS-SWIFT-008: loadHTMLString with string interpolation
    func showProfile(userBio: String) {
        webView.loadHTMLString("<html><body><p>\(userBio)</p></body></html>", baseURL: nil)
    }

    // GTSS-SWIFT-008: evaluateJavaScript with concatenation
    func runScript(userInput: String) {
        let script = "alert(" + userInput + ")"
        webView.evaluateJavaScript(script)
    }
}

// VULNERABLE: Insecure data storage
func saveCredentials(username: String, password: String) {
    // GTSS-SWIFT-009: Password stored in UserDefaults
    UserDefaults.standard.set(password, forKey: "password")
    UserDefaults.standard.set(username, forKey: "username")
}

func saveAuthToken(token: String) {
    // GTSS-SWIFT-009: Auth token in UserDefaults
    UserDefaults.standard.set(token, forKey: "authToken")
}

// VULNERABLE: UIWebView usage
class LegacyWebViewController: UIViewController {
    // GTSS-SWIFT-004: Deprecated UIWebView
    let webView = UIWebView(frame: .zero)

    override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(webView)
    }
}

// VULNERABLE: Insecure random
func generateOTP() -> String {
    // GTSS-SWIFT-006: C library rand() for security token
    srand(UInt32(time(nil)))
    let otp = rand() % 1000000
    return String(format: "%06d", otp)
}

// VULNERABLE: Jailbreak detection (easily bypassed)
func isDeviceJailbroken() -> Bool {
    // GTSS-SWIFT-010: Common jailbreak file check
    if FileManager.default.fileExists(atPath: "/Applications/Cydia.app") {
        return true
    }
    if FileManager.default.fileExists(atPath: "/Library/MobileSubstrate/MobileSubstrate.dylib") {
        return true
    }
    return false
}
