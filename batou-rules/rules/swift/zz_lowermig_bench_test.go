package swift

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a Swift-rule-heavy ScanContext: a spread of lines the Swift
// rules scan, most of which carry no trigger (the realistic majority case where
// the per-(pattern × line) re-lowering of the GFind/GMatch prefilter gate
// dominated). LinesLower is populated exactly as the scanner does before fanning
// out rules, so the migrated *Lower call sites take the shared-lowered-line fast
// path.
func lowermigCtx(base []string) *rules.ScanContext {
	var lines []string
	for len(lines) < 210 {
		lines = append(lines, base...)
	}
	content := strings.Join(lines, "\n")
	lower := make([]string, len(lines))
	for i, l := range lines {
		lower[i] = strings.ToLower(l)
	}
	return &rules.ScanContext{
		FilePath:     "/app/Sources/App/routes.swift",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangSwift,
	}
}

// swiftBenchRules returns every registered Swift rule (BATOU-SWIFT-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func swiftBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-SWIFT-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigSwiftBench = lowermigCtx([]string{
	"import Vapor",
	"func routes(_ app: Application) throws {",
	"    let name = req.query[\"name\"] ?? \"\"",
	"    let session = URLSession(configuration: config)",
	"    config.tlsMinimumSupportedProtocolVersion = .TLSv10",
	"    completionHandler(.useCredential, URLCredential(trust: serverTrust))",
	"    let pred = NSPredicate(format: \"name == \\(name)\")",
	"    let q = \"SELECT * FROM users WHERE name = '\\(name)'\"",
	"    webView.evaluateJavaScript(\"x = \\(name)\")",
	"    let html = \"<div>\\(name)</div>\"",
	"    let process = Process()",
	"    process.arguments = [\"-c\", name]",
	"    let data = try Data(contentsOf: URL(fileURLWithPath: name))",
	"    FileManager.default.removeItem(atPath: name)",
	"    let obj = NSKeyedUnarchiver.unarchiveObject(with: data)",
	"    UserDefaults.standard.set(token, forKey: \"password\")",
	"    let key = \"AKIAIOSFODNN7EXAMPLE\"",
	"    let r = arc4random()",
	"    let query: [String: Any] = [kSecAttrAccessible as String: kSecAttrAccessibleAlways]",
	"    let wv = UIWebView()",
	"    prefs.javaScriptEnabled = true",
	"    return req.redirect(to: name)",
	"    let total = items.reduce(0) { $0 + $1.amount }",
	"    app.logger.info(\"processed \\(count) records\")",
	"}",
})

// BenchmarkSwiftScan_LowerMigrated runs every Swift rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration swift/*.go to quantify the per-(pattern × line) re-lowering removed
// by the *Lower migration.
func BenchmarkSwiftScan_LowerMigrated(b *testing.B) {
	rs := swiftBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigSwiftBench))
		}
	}
	_ = n
}
