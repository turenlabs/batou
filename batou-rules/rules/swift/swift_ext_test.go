package swift

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// ---------------------------------------------------------------------------
// BATOU-SWIFT-011: Swift URLSession with disabled SSL validation
// ---------------------------------------------------------------------------

func TestSwift011_URLSessionNoSSL(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "disposition useCredential",
			content: `import Foundation
func handle() {
    var disposition = URLSession.AuthChallengeDisposition.performDefaultHandling
    let serverTrust = challenge.protectionSpace.serverTrust
    disposition = .useCredential
}`,
			want: true,
		},
		{
			name: "URLCredential trust",
			content: `import Foundation
func handle() {
    let serverTrust = challenge.protectionSpace.serverTrust!
    let cred = URLCredential(trust: serverTrust)
}`,
			want: true,
		},
		{
			name: "completionHandler useCredential",
			content: `import Foundation
func handle() {
    let serverTrust = challenge.protectionSpace.serverTrust!
    completionHandler(.useCredential, URLCredential(trust: serverTrust))
}`,
			want: true,
		},
		{
			// reURLSessionNoValidate gate (.serverTrust) absent -> no finding.
			name: "no serverTrust reference gates out",
			content: `import Foundation
func handle() {
    disposition = .useCredential
}`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Net.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-011")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-011")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-012: Swift Keychain access without authentication
// ---------------------------------------------------------------------------

func TestSwift012_KeychainNoAuth(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "SecItemAdd with AccessibleAlways",
			content: `import Security
func save(data: Data) {
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessible as String: kSecAttrAccessibleAlways,
        kSecValueData as String: data
    ]
    SecItemAdd(q as CFDictionary, nil)
}`,
			want: true,
		},
		{
			name: "SecItemCopyMatching with AlwaysThisDeviceOnly",
			content: `import Security
func read() {
    let q: [String: Any] = [
        kSecAttrAccessible as String: kSecAttrAccessibleAlwaysThisDeviceOnly
    ]
    SecItemCopyMatching(q as CFDictionary, nil)
}`,
			want: true,
		},
		{
			// Has SecItemAdd but uses WhenUnlocked -> reKeychainAlways never matches.
			name: "safe accessibility level",
			content: `import Security
func save(data: Data) {
    let q: [String: Any] = [
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
        kSecValueData as String: data
    ]
    SecItemAdd(q as CFDictionary, nil)
}`,
			want: false,
		},
		{
			// No SecItemAdd/SecItemCopyMatching present -> file gate returns nil
			// even though kSecAttrAccessibleAlways appears.
			name: "no keychain call gates out",
			content: `import Security
let accessibility = kSecAttrAccessibleAlways`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Keychain.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-012")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-012")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-013: Swift UserDefaults storing sensitive data
// ---------------------------------------------------------------------------

func TestSwift013_UserDefaultsSensitive(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "sensitive key token",
			content: `import Foundation
func save(_ t: String) {
    UserDefaults.standard.set(t, forKey: "authToken")
}`,
			want: true,
		},
		{
			name: "sensitive key password",
			content: `import Foundation
UserDefaults.standard.set(pwd, forKey: "user_password")`,
			want: true,
		},
		{
			name: "non-sensitive preference key",
			content: `import Foundation
func save(_ theme: String) {
    UserDefaults.standard.set(theme, forKey: "theme")
}`,
			want: false,
		},
		{
			// reUserDefaultsSet file gate absent.
			name: "no UserDefaults set gates out",
			content: `import Foundation
let x = UserDefaults.standard.string(forKey: "token")`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Store.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-013")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-013")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-014: Swift WKWebView JS enabled without content rules
// ---------------------------------------------------------------------------

func TestSwift014_WKWebViewJS(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "javascript enabled no protections",
			content: `import WebKit
func setup(_ webView: WKWebView) {
    webView.configuration.preferences.javaScriptEnabled = true
}`,
			want: true,
		},
		{
			// Both content rules AND nav delegate present -> skip.
			name: "content rules and nav delegate safe",
			content: `import WebKit
class C: WKNavigationDelegate {
    func setup(_ webView: WKWebView) {
        webView.configuration.preferences.javaScriptEnabled = true
        webView.navigationDelegate = self
        let store = WKContentRuleListStore.default()
    }
}`,
			want: false,
		},
		{
			// Only content rules but no nav delegate -> still flagged
			// (skip requires BOTH).
			name: "only content rules still flagged",
			content: `import WebKit
func setup(_ webView: WKWebView) {
    webView.configuration.preferences.javaScriptEnabled = true
    let store = WKContentRuleListStore.default()
}`,
			want: true,
		},
		{
			name: "javascript not enabled",
			content: `import WebKit
func setup(_ webView: WKWebView) {
    webView.configuration.preferences.javaScriptEnabled = false
}`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/WebView.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-014")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-014")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-015: Swift hardcoded encryption key/IV
// ---------------------------------------------------------------------------

func TestSwift015_HardcodedKey(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "byte array key",
			content: `import Foundation
let key: [UInt8] = [0x00, 0x11, 0x22, 0x33]`,
			want: true,
		},
		{
			name: "iv byte array",
			content: `import Foundation
let iv = [0xAA, 0xBB, 0xCC]`,
			want: true,
		},
		{
			name: "aesKey string literal",
			content: `import Foundation
let aesKey = "0123456789abcdef"`,
			want: true,
		},
		{
			name: "key from Data base64",
			content: `import Foundation
let key = Data(base64Encoded: "c2VjcmV0a2V5MTIzNA==")`,
			want: true,
		},
		{
			name: "runtime generated key safe",
			content: `import CryptoKit
let key = SymmetricKey(size: .bits256)`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Crypto.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-015")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-015")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-016: Swift string interpolation in SQL/predicate
// ---------------------------------------------------------------------------

func TestSwift016_SQLPredicateInterp(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "NSPredicate interpolation",
			content: `import Foundation
let p = NSPredicate(format: "name == \(userInput)")`,
			want: true,
		},
		{
			name: "NSPredicate concatenation",
			content: `import Foundation
let p = NSPredicate(format: "name == " + userInput)`,
			want: true,
		},
		{
			name: "SQL string interpolation",
			content: `import Foundation
let q = "SELECT * FROM users WHERE id = \(id)"`,
			want: true,
		},
		{
			name: "parameterized predicate safe",
			content: `import Foundation
let p = NSPredicate(format: "name == %@", userInput)`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Query.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-016")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-016")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-017: Swift insecure NSCoding deserialization
// ---------------------------------------------------------------------------

func TestSwift017_NSCodingDeser(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "unarchiveObject",
			content: `import Foundation
func load(_ data: Data) -> Any? {
    return NSKeyedUnarchiver.unarchiveObject(with: data)
}`,
			want: true,
		},
		{
			// reNSSecureCoding present anywhere in file -> whole rule skips.
			name: "NSSecureCoding present skips",
			content: `import Foundation
class Safe: NSObject, NSSecureCoding {
    static var supportsSecureCoding = true
}
func load(_ data: Data) -> Any? {
    return NSKeyedUnarchiver.unarchiveObject(with: data)
}`,
			want: false,
		},
		{
			name: "secure unarchivedObject ofClass safe",
			content: `import Foundation
func load(_ data: Data) throws -> MyModel? {
    return try NSKeyedUnarchiver.unarchivedObject(ofClass: MyModel.self, from: data)
}`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Archive.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-017")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-017")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-018: Swift App Transport Security disabled
// ---------------------------------------------------------------------------

func TestSwift018_ATSDisabled(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "ATS arbitrary loads true",
			content: `<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>`,
			want: true,
		},
		{
			// NSAppTransportSecurity file gate absent.
			name: "no ATS dict gates out",
			content: `<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>`,
			want: false,
		},
		{
			// Present but set to false -> reATSTrueValue not nearby.
			name: "ATS arbitrary loads false safe",
			content: `<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <false/>
    </dict>
</dict>`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Config.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-018")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-018")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-019: Vapor open redirect
// ---------------------------------------------------------------------------

func TestSwift019_VaporRedirect(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "redirect to user variable",
			content: `import Vapor
func handler(_ req: Request) -> Response {
    let target = req.query["url"] ?? "/"
    return req.redirect(to: target)
}`,
			want: true,
		},
		{
			name: "location header set",
			content: `import Vapor
func handler(_ req: Request) -> Response {
    let dest = req.query["next"]!
    var resp = Response()
    resp.headers.replaceOrAdd(name: .location, value: dest)
    return resp
}`,
			want: true,
		},
		{
			// Literal redirect target -> reRedirectLiteral suppresses var branch.
			name: "literal redirect safe",
			content: `import Vapor
func handler(_ req: Request) -> Response {
    let x = req.query["url"]
    return req.redirect(to: "/home")
}`,
			want: false,
		},
		{
			// Allowlist host check present -> rule skips.
			name: "allowlist check safe",
			content: `import Vapor
func handler(_ req: Request) -> Response {
    let target = req.query["url"] ?? "/"
    guard allowedHosts.contains(target) else { return req.redirect(to: "/") }
    return req.redirect(to: target)
}`,
			want: false,
		},
		{
			// No Vapor request source present -> rule returns nil.
			name: "no vapor source gates out",
			content: `import Vapor
func handler() -> Response {
    let target = computeTarget()
    return someResponse.redirect(to: target)
}`,
			want: false,
		},
		{
			// Int guard restricts input -> rule skips.
			name: "int guard safe",
			content: `import Vapor
func handler(_ req: Request) -> Response {
    guard let page = Int(req.query["page"] ?? "") else { return req.redirect(to: "/") }
    return req.redirect(to: target)
}`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Routes.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-019")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-019")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-020: Vapor XSS via HTML response
// ---------------------------------------------------------------------------

func TestSwift020_VaporXSS(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "html interpolation",
			content: `import Vapor
func page(_ req: Request) -> Response {
    let name = req.query["name"] ?? ""
    let html = "<html><body><h1>\(name)</h1></body></html>"
    return Response(status: .ok, body: .init(string: html))
}`,
			want: true,
		},
		{
			// Leaf renderer present -> auto-escape, skip.
			name: "leaf renderer safe",
			content: `import Vapor
func page(_ req: Request) -> EventLoopFuture<View> {
    let name = req.query["name"] ?? ""
    let html = "<div>\(name)</div>"
    return req.view.render("page", ["name": name])
}`,
			want: false,
		},
		{
			// HTML escaping present -> skip.
			name: "html escape safe",
			content: `import Vapor
func page(_ req: Request) -> Response {
    var name = req.query["name"] ?? ""
    name = name.replacingOccurrences(of: "<", with: "&lt;")
    let html = "<div>\(name)</div>"
    return Response(status: .ok, body: .init(string: html))
}`,
			want: false,
		},
		{
			// No HTML tags at all -> rule returns nil.
			name: "no html tags gates out",
			content: `import Vapor
func page(_ req: Request) -> Response {
    let name = req.query["name"] ?? ""
    return Response(status: .ok, body: .init(string: name))
}`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Web.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-020")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-020")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-021: Swift Process/command injection
// ---------------------------------------------------------------------------

func TestSwift021_ProcessInjection(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "process args from user input",
			content: `import Foundation
func run(_ req: Request) {
    let cmd = req.query["cmd"] ?? ""
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/sh")
    task.arguments = ["-c", cmd]
    task.run()
}`,
			want: true,
		},
		{
			// Allowlist present -> skip.
			name: "allowlist command safe",
			content: `import Foundation
func run(_ req: Request) {
    let cmd = req.query["cmd"] ?? ""
    guard allowedCommands.contains(cmd) else { return }
    let task = Process()
    task.arguments = [cmd]
    task.run()
}`,
			want: false,
		},
		{
			// No run/launch call -> file gate returns nil.
			name: "no run call gates out",
			content: `import Foundation
func build(_ req: Request) {
    let cmd = req.query["cmd"] ?? ""
    let task = Process()
    task.arguments = [cmd]
}`,
			want: false,
		},
		{
			// No user source -> rule returns nil.
			name: "no user source gates out",
			content: `import Foundation
func run() {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/ls")
    task.arguments = ["-la"]
    task.run()
}`,
			want: false,
		},
		{
			// Enum decode restricts input -> skip.
			name: "enum decode safe",
			content: `import Foundation
enum Cmd: String, Codable { case list, status }
func run(_ req: Request) {
    let cmd = req.query["cmd"] ?? ""
    let task = Process()
    task.arguments = [cmd]
    task.run()
}`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Exec.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-021")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-021")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-022: Swift path traversal via FileManager/Data
// ---------------------------------------------------------------------------

func TestSwift022_PathTraversal(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "FileManager contents from user path",
			content: `import Foundation
func read(_ req: Request) {
    let path = req.query["file"] ?? ""
    let data = FileManager.default.contents(atPath: path)
}`,
			want: true,
		},
		{
			name: "Data contentsOf user path",
			content: `import Foundation
func read(_ req: Request) throws {
    let name = req.parameters.get("name")!
    let data = try Data(contentsOf: URL(fileURLWithPath: name))
}`,
			want: true,
		},
		{
			// rePathSafe present (standardizedFileURL) -> skip.
			name: "path sanitization safe",
			content: `import Foundation
func read(_ req: Request) {
    let path = req.query["file"] ?? ""
    let url = URL(fileURLWithPath: path).standardizedFileURL
    let data = FileManager.default.contents(atPath: url.path)
}`,
			want: false,
		},
		{
			// No user source -> rule returns nil.
			name: "no user source gates out",
			content: `import Foundation
func read() {
    let data = FileManager.default.contents(atPath: "/etc/config")
}`,
			want: false,
		},
		{
			// UUID guard restricts input -> skip.
			name: "uuid guard safe",
			content: `import Foundation
func read(_ req: Request) {
    let raw = req.query["id"] ?? ""
    guard let id = UUID(uuidString: raw) else { return }
    let data = FileManager.default.contents(atPath: id.uuidString)
}`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Files.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-022")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-022")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-023: Swift insecure deserialization
// ---------------------------------------------------------------------------

func TestSwift023_InsecureDeser(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "NSKeyedUnarchiver unarchiveObject",
			content: `import Foundation
func load(_ data: Data) -> Any? {
    return NSKeyedUnarchiver.unarchiveObject(with: data)
}`,
			want: true,
		},
		{
			name: "JSONSerialization jsonObject",
			content: `import Foundation
func parse(_ data: Data) throws -> Any {
    return try JSONSerialization.jsonObject(with: data, options: [])
}`,
			want: true,
		},
		{
			name: "PropertyListSerialization",
			content: `import Foundation
func parse(_ data: Data) throws -> Any {
    return try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
}`,
			want: true,
		},
		{
			name: "NSClassFromString dynamic class",
			content: `import Foundation
func make(_ name: String) -> AnyClass? {
    return NSClassFromString(name)
}`,
			want: true,
		},
		{
			name: "decodeObject forKey",
			content: `import Foundation
func decode(_ coder: NSCoder) -> Any? {
    return coder.decodeObject(forKey: "payload")
}`,
			want: true,
		},
		{
			// reSecureCoding present -> whole rule skips.
			name: "secure coding skips",
			content: `import Foundation
class Model: NSObject, NSSecureCoding {
    static var supportsSecureCoding = true
}
func load(_ data: Data) -> Any? {
    return NSKeyedUnarchiver.unarchiveObject(with: data)
}`,
			want: false,
		},
		{
			name: "Codable decoder safe",
			content: `import Foundation
func load(_ data: Data) throws -> MyModel {
    return try JSONDecoder().decode(MyModel.self, from: data)
}`,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := testutil.ScanContent(t, "/app/Deser.swift", tc.content)
			if tc.want {
				testutil.MustFindRule(t, result, "BATOU-SWIFT-023")
			} else {
				testutil.MustNotFindRule(t, result, "BATOU-SWIFT-023")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Rule metadata sanity (exercises ID/Name/Description/Severity/Languages
// for the extension + bench rules without locking in incidental behavior).
// ---------------------------------------------------------------------------

func TestSwiftExtRuleMetadata(t *testing.T) {
	type ruleIface interface {
		ID() string
		Name() string
		Description() string
		DefaultSeverity() rules.Severity
		Languages() []rules.Language
	}

	registered := []ruleIface{
		&SwiftURLSessionNoSSL{},
		&SwiftKeychainNoAuth{},
		&SwiftUserDefaultsSensitive{},
		&SwiftWKWebViewJS{},
		&SwiftHardcodedKey{},
		&SwiftSQLPredicateInterp{},
		&SwiftNSCodingDeser{},
		&SwiftATSDisabled{},
		&SwiftVaporRedirect{},
		&SwiftVaporXSS{},
		&SwiftProcessInjection{},
		&SwiftPathTraversal{},
		&SwiftInsecureDeser{},
	}

	seen := make(map[string]bool)
	for _, r := range registered {
		id := r.ID()
		if id == "" {
			t.Errorf("%T returned empty ID", r)
		}
		if seen[id] {
			t.Errorf("duplicate rule ID %q", id)
		}
		seen[id] = true

		if r.Name() == "" {
			t.Errorf("%s returned empty Name", id)
		}
		if r.Description() == "" {
			t.Errorf("%s returned empty Description", id)
		}
		langs := r.Languages()
		if len(langs) == 0 {
			t.Errorf("%s returned no Languages", id)
		}
		foundSwift := false
		for _, l := range langs {
			if l == rules.LangSwift {
				foundSwift = true
			}
		}
		if !foundSwift {
			t.Errorf("%s does not list LangSwift", id)
		}
	}
}
