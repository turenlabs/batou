package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — argument-label sink keying (matcher arg-label gate)
//
// Catalog sinks written in the Apple argument-label form `Base(label:)` —
// String(contentsOfFile:), Data(contentsOf:), FileHandle(forReadingAtPath:),
// nodes(forXPath:), NSPredicate(format:) — were previously DEAD: the tsflow
// matcher's extractMethodNames normalised the trailing ":" to "." and keyed
// the entry under the mangled final component ")", so the bare call name
// (String / Data / FileHandle / nodes / NSPredicate) never resolved them.
// The fix keys these under the bare callable base and gates the match on the
// call carrying the required argument label. These tests pin the behaviour.
// =========================================================================

func TestSwift_ArgLabelSink_StringContentsOfFile(t *testing.T) {
	code := `
import Vapor

func handleFileDownload(req: Request) throws -> String {
    let filename = req.parameters.get("filename")!
    let contents = try String(contentsOfFile: "/var/data/" + filename, encoding: .utf8)
    return contents
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow for req.parameters -> String(contentsOfFile:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestSwift_ArgLabelSink_DataContentsOf(t *testing.T) {
	code := `
import Vapor

func handleBinaryDownload(req: Request) throws -> Data {
    let path = req.query["path"] ?? ""
    let url = URL(fileURLWithPath: "/uploads/" + path)
    let data = try Data(contentsOf: url)
    return data
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow for req.query -> Data(contentsOf:)")
	}
}

func TestSwift_ArgLabelSink_FileHandleForReadingAtPath(t *testing.T) {
	code := `
import Vapor

func handleFileStream(req: Request) throws {
    let userPath = req.parameters.get("path")!
    guard let handle = FileHandle(forReadingAtPath: "/documents/" + userPath) else { return }
    _ = handle
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow for req.parameters -> FileHandle(forReadingAtPath:)")
	}
}

func TestSwift_ArgLabelSink_NodesForXPath(t *testing.T) {
	code := `
import Hummingbird

func searchXML(request: HBRequest) throws -> String {
    let query = request.parameters.get("query") ?? ""
    let doc = try XMLDocument(data: Data())
    let results = try doc.nodes(forXPath: "//item[name='\(query)']")
    return results.map { $0.stringValue ?? "" }.joined()
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath flow for request.parameters -> doc.nodes(forXPath:)")
	}
}

func TestSwift_ArgLabelSink_NSPredicateFormatInterpolated(t *testing.T) {
	// Injection-text param name `name` is seeded; interpolated into the
	// NSPredicate format string (arg 0) => predicate injection.
	code := `
import Foundation

func searchUsers(name: String) -> NSPredicate {
    return NSPredicate(format: "name == '\(name)'")
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected predicate-injection flow for name -> NSPredicate(format:)")
	}
}

// The arg-label gate must NOT fire on a DIFFERENT label that shares the same
// bare callable base. `String(describing:)` and a plain `String(x)` cast are
// not file reads even though they key under `String` like
// `String(contentsOfFile:)`.
func TestSwift_ArgLabelGate_StringDescribing_NotFileRead(t *testing.T) {
	code := `
import Vapor

func render(req: Request) -> String {
    let n = req.query["n"] ?? ""
    let s = String(describing: n)
    return s
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Errorf("String(describing:) must not match the String(contentsOfFile:) file-read sink; got %s", f.Sink.ID)
		}
	}
}

// =========================================================================
// Swift — WKWebView eval/HTML sinks (receiver alias + line_string_literal
// interpolation + injection-text param seeding).
// =========================================================================

func TestSwift_WebView_EvaluateJavaScript_Interpolated(t *testing.T) {
	code := `
import WebKit

class C {
    var webView: WKWebView!
    func displayUserName(name: String) {
        webView.evaluateJavaScript("x = '\(name)'")
    }
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for name -> webView.evaluateJavaScript (interpolated)")
	}
}

func TestSwift_WebView_LoadHTMLString_Interpolated(t *testing.T) {
	code := `
import WebKit

class C {
    var webView: WKWebView!
    func renderProfile(bio: String) {
        webView.loadHTMLString("<div>\(bio)</div>", baseURL: nil)
    }
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected html-output flow for bio -> webView.loadHTMLString (interpolated)")
	}
}

// =========================================================================
// Swift — FP safety: the safe shapes used by the safe fixtures must NOT fire.
// =========================================================================

func TestSwift_SafeXPath_EscapedApostrophe_NoFlow(t *testing.T) {
	code := `
import Foundation

func searchXML(query: String) throws -> [String] {
    let safeQuery = query.replacingOccurrences(of: "'", with: "&apos;")
    let xmlData = try Data(contentsOf: URL(fileURLWithPath: "/data/catalog.xml"))
    let doc = try XMLDocument(data: xmlData)
    let results = try doc.nodes(forXPath: "//item[name='\(safeQuery)']")
    return results.map { $0.stringValue ?? "" }
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath {
			t.Error("escaped XPath must not fire (replacingOccurrences sanitizer + hardcoded xmlData)")
		}
	}
}

func TestSwift_SafeRedirect_HasPrefixGuard_NoFlow(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) throws -> Response {
    let url = req.query["redirect"] ?? "/"
    guard url.hasPrefix("https://") else { throw Abort(.badRequest) }
    return req.redirect(to: url)
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Error("hasPrefix(\"https://\") guard must clear redirect taint on fall-through")
		}
	}
}

func TestSwift_SafeFileRead_HardcodedPath_NoFlow(t *testing.T) {
	// No user input anywhere — a hardcoded resource read must not fire.
	code := `
import Foundation

func readConfig() throws -> String {
    return try String(contentsOfFile: "/etc/app/config.json", encoding: .utf8)
}
`
	flows := Analyze(code, "/app/h.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("hardcoded-path file read must not fire")
		}
	}
}
