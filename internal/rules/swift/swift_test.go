package swift

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-SWIFT-001: Insecure URLSession ---

func TestSwift001_InsecureURLSession_TrustAll(t *testing.T) {
	content := `import Foundation

class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
        completionHandler(.useCredential, credential)
    }
}`
	result := testutil.ScanContent(t, "/app/NetworkManager.swift", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-SWIFT-001", "BATOU-SWIFT-011")
}

func TestSwift001_InsecureURLSession_WithPinning_Safe(t *testing.T) {
	content := `import Foundation

class PinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let serverKey = SecTrustCopyPublicKey(serverTrust)
        if serverKey == pinnedKey {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}`
	result := testutil.ScanContent(t, "/app/NetworkManager.swift", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-001")
}

// --- BATOU-SWIFT-002: App Transport Security Bypass ---

func TestSwift002_ATSBypass_Plist(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>`
	result := testutil.ScanContent(t, "/app/Info.plist", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-002")
}

func TestSwift002_ATSBypass_InsecureHTTP(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSExceptionDomains</key>
        <dict>
            <key>example.com</key>
            <dict>
                <key>NSExceptionAllowsInsecureHTTPLoads</key>
                <true/>
            </dict>
        </dict>
    </dict>
</dict>
</plist>`
	result := testutil.ScanContent(t, "/app/Info.plist", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-002")
}

func TestSwift002_ATSBypass_Disabled_Safe(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <false/>
    </dict>
</dict>
</plist>`
	result := testutil.ScanContent(t, "/app/Info.plist", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-002")
}

// --- BATOU-SWIFT-003: Insecure Keychain Storage ---

func TestSwift003_KeychainAccessibleAlways(t *testing.T) {
	content := `import Security

func saveToKeychain(data: Data) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleAlways,
        kSecValueData as String: data
    ]
    SecItemAdd(query as CFDictionary, nil)
}`
	result := testutil.ScanContent(t, "/app/KeychainHelper.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-003")
}

func TestSwift003_KeychainAlwaysThisDeviceOnly(t *testing.T) {
	content := `import Security

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessible as String: kSecAttrAccessibleAlwaysThisDeviceOnly,
    kSecValueData as String: tokenData
]`
	result := testutil.ScanContent(t, "/app/KeychainHelper.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-003")
}

func TestSwift003_KeychainWhenUnlocked_Safe(t *testing.T) {
	content := `import Security

func saveToKeychain(data: Data) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
        kSecValueData as String: data
    ]
    SecItemAdd(query as CFDictionary, nil)
}`
	result := testutil.ScanContent(t, "/app/KeychainHelper.swift", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-003")
}

// --- BATOU-SWIFT-004: UIWebView Usage ---

func TestSwift004_UIWebViewUsage(t *testing.T) {
	content := `import UIKit

class WebViewController: UIViewController {
    let webView = UIWebView(frame: .zero)

    override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(webView)
        webView.loadRequest(URLRequest(url: URL(string: "https://example.com")!))
    }
}`
	result := testutil.ScanContent(t, "/app/WebViewController.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-004")
}

func TestSwift004_WKWebView_Safe(t *testing.T) {
	content := `import WebKit

class WebViewController: UIViewController {
    let webView = WKWebView(frame: .zero)

    override func viewDidLoad() {
        super.viewDidLoad()
        view.addSubview(webView)
        webView.load(URLRequest(url: URL(string: "https://example.com")!))
    }
}`
	result := testutil.ScanContent(t, "/app/WebViewController.swift", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-004")
}

// --- BATOU-SWIFT-005: Hardcoded Secrets ---

func TestSwift005_HardcodedAPIKey(t *testing.T) {
	content := `import Foundation

class APIClient {
    let apiKey = "sk_live_abcdefghijklmnopqrstuvwxyz123456"

    func makeRequest() {
        // use apiKey
    }
}`
	result := testutil.ScanContent(t, "/app/APIClient.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-005")
}

func TestSwift005_HardcodedPassword(t *testing.T) {
	content := `import Foundation

let databasePassword = "super_secret_db_password_2024"
`
	result := testutil.ScanContent(t, "/app/Config.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-005")
}

func TestSwift005_HardcodedAWSKey(t *testing.T) {
	content := `import Foundation

let awsAccessKey = "AKIAJ4MBRZBKQW9HWCQA"
`
	result := testutil.ScanContent(t, "/app/AWSConfig.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-005")
}

func TestSwift005_EnvVariable_Safe(t *testing.T) {
	content := `import Foundation

let apiKey = ProcessInfo.processInfo.environment["API_KEY"] ?? ""
`
	result := testutil.ScanContent(t, "/app/Config.swift", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-005")
}

// --- BATOU-SWIFT-006: Insecure Random ---

func TestSwift006_SrandRand(t *testing.T) {
	content := `import Foundation

func generateToken() -> String {
    srand(UInt32(time(nil)))
    let token = rand() % 1000000
    return String(token)
}`
	result := testutil.ScanContent(t, "/app/TokenGenerator.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-006")
}

func TestSwift006_SecRandom_Safe(t *testing.T) {
	content := `import Security

func generateSecureToken() -> Data {
    var bytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    return Data(bytes)
}`
	result := testutil.ScanContent(t, "/app/TokenGenerator.swift", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-006")
}

// --- BATOU-SWIFT-007: SQL Injection in SQLite ---

func TestSwift007_SQLiteStringInterpolation(t *testing.T) {
	content := `import SQLite3

func findUser(name: String) {
    var db: OpaquePointer?
    sqlite3_open("test.db", &db)
    let query = "SELECT * FROM users WHERE name = '\(name)'"
    sqlite3_exec(db, query, nil, nil, nil)
}`
	result := testutil.ScanContent(t, "/app/Database.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-007")
}

func TestSwift007_SQLiteParameterized_Safe(t *testing.T) {
	content := `import SQLite3

func findUser(name: String) {
    var db: OpaquePointer?
    sqlite3_open("test.db", &db)
    var stmt: OpaquePointer?
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name = ?", -1, &stmt, nil)
    sqlite3_bind_text(stmt, 1, name, -1, nil)
    sqlite3_step(stmt)
}`
	result := testutil.ScanContent(t, "/app/Database.swift", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-007")
}

// --- BATOU-SWIFT-008: WKWebView JavaScript Injection ---

func TestSwift008_EvaluateJSInterpolation(t *testing.T) {
	content := `import WebKit

class WebController {
    var webView: WKWebView!

    func updateTitle(userInput: String) {
        webView.evaluateJavaScript("document.title = '\(userInput)'")
    }
}`
	result := testutil.ScanContent(t, "/app/WebController.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-008")
}

func TestSwift008_LoadHTMLStringInterpolation(t *testing.T) {
	content := `import WebKit

class WebController {
    var webView: WKWebView!

    func showContent(userInput: String) {
        webView.loadHTMLString("<html><body><h1>\(userInput)</h1></body></html>", baseURL: nil)
    }
}`
	result := testutil.ScanContent(t, "/app/WebController.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-008")
}

func TestSwift008_StaticJS_Safe(t *testing.T) {
	content := `import WebKit

class WebController {
    var webView: WKWebView!

    func getTitle() {
        webView.evaluateJavaScript("document.title") { result, error in
            print(result ?? "")
        }
    }
}`
	result := testutil.ScanContent(t, "/app/WebController.swift", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-008")
}

// --- BATOU-SWIFT-009: Insecure Data Storage ---

func TestSwift009_UserDefaultsPassword(t *testing.T) {
	content := `import Foundation

func saveCredentials(password: String) {
    UserDefaults.standard.set(password, forKey: "password")
}`
	result := testutil.ScanContent(t, "/app/AuthManager.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-009")
}

func TestSwift009_UserDefaultsToken(t *testing.T) {
	content := `import Foundation

func saveSession(token: String) {
    UserDefaults.standard.set(token, forKey: "authToken")
}`
	result := testutil.ScanContent(t, "/app/SessionManager.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-009")
}

func TestSwift009_UserDefaultsPreference_Safe(t *testing.T) {
	content := `import Foundation

func savePreference(theme: String) {
    UserDefaults.standard.set(theme, forKey: "theme")
}`
	result := testutil.ScanContent(t, "/app/Settings.swift", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-009")
}

// --- BATOU-SWIFT-010: Jailbreak Detection Bypass ---

func TestSwift010_JailbreakFileCheck(t *testing.T) {
	content := `import Foundation

func isJailbroken() -> Bool {
    if FileManager.default.fileExists(atPath: "/Applications/Cydia.app") {
        return true
    }
    return false
}`
	result := testutil.ScanContent(t, "/app/SecurityCheck.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-010")
}

func TestSwift010_JailbreakURLScheme(t *testing.T) {
	content := `import UIKit

func isJailbroken() -> Bool {
    return UIApplication.shared.canOpenURL(URL(string: "cydia://package")!)
}`
	result := testutil.ScanContent(t, "/app/SecurityCheck.swift", content)
	testutil.MustFindRule(t, result, "BATOU-SWIFT-010")
}

func TestSwift010_NoJailbreakCheck_Safe(t *testing.T) {
	content := `import Foundation

func validateDevice() -> Bool {
    // Use Apple's Device Check API
    return DCDevice.current.isSupported
}`
	result := testutil.ScanContent(t, "/app/SecurityCheck.swift", content)
	testutil.MustNotFindRule(t, result, "BATOU-SWIFT-010")
}
