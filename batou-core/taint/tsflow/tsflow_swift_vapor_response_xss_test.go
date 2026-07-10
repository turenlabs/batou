package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — Vapor HTTP-response reflected-XSS tests (CWE-79)
// =========================================================================
//
// Returning attacker-controlled data inside an HTML response body is the
// canonical Vapor reflected-XSS vector — the parity equivalent of Java
// `response.getWriter().println(name)` (BATOU-XSS-029), which Batou catches
// at dataflow tier (CWE-79, conf 1.0). The idiomatic Vapor constructor form
//
//     return Response(status: .ok, body: .init(string: "<h1>\(name)</h1>"))
//
// builds a Response directly from an interpolated user string.
//
// This was a LANGUAGE-PARITY gap: the `swift.vapor.response.body` sink was
// DEAD at the dataflow tier because its MethodName `Response(body:)` carried a
// parenthetical qualifier that extractMethodNames mangled into the unreachable
// key `)` (tsflow keys the constructor call `Response(...)` on the bare type
// name `Response`). The shape only reached the Layer-1 regex tier
// (BATOU-SWIFT-020, conf 0.5, non-blocking). Re-keyed to a wildcard ObjectType
// + bare MethodName `Response` with a constructor-anchored Pattern, flagging
// all args (the `status:` arg is always an enum literal, never tainted).
//
// SAFE forms that must NOT fire: a constant body, an HTML-escaped value, and a
// JSON content-type response (neutralized by swift.vapor.response.json).

// Tainted user input interpolated into a Response HTML body — the injection
// form. The catching-language equivalent (Java getWriter().println) fires at
// dataflow tier; Swift must reach the same tier.
func TestSwift_VaporResponse_XSS_TaintedInterpolation(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) throws -> Response {
    let name = req.query[String.self, at: "name"] ?? ""
    let html = "<h1>Hello \(name)</h1>"
    return Response(status: .ok, body: .init(string: html))
}
`
	flows := Analyze(code, "/app/GreetController.swift", rules.LangSwift)
	if !hasFlowFromSink(flows, "swift.vapor.response.body", taint.SnkHTMLOutput) &&
		!hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Errorf("expected CWE-79 HTML-output flow for req.query -> Response(body: \\(name)); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Single-arg constructor form `Response(body: .init(string: html))` (no
// preceding status: arg) — verifies the all-args (-1) flagging is robust to
// argument ordering.
func TestSwift_VaporResponse_XSS_BodyFirstArg(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) throws -> Response {
    let name = req.query[String.self, at: "name"] ?? ""
    return Response(body: .init(string: "<p>\(name)</p>"))
}
`
	flows := Analyze(code, "/app/EchoController.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Errorf("expected CWE-79 HTML-output flow for Response(body: \\(name)); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// SAFE: constant HTML body with no interpolated user input. Must NOT fire.
func TestSwift_VaporResponse_XSS_Constant_Safe(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) throws -> Response {
    let html = "<h1>Hello World</h1>"
    return Response(status: .ok, body: .init(string: html))
}
`
	flows := Analyze(code, "/app/StaticController.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO HTML flow for constant body, got %s -> %s (sinkID=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// SAFE: HTML-escaped value (replacingOccurrences "<" -> "&lt;"). The
// swift.string.xmlescape sanitizer neutralizes SnkHTMLOutput. Must NOT fire.
func TestSwift_VaporResponse_XSS_Escaped_Safe(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) throws -> Response {
    let name = req.query[String.self, at: "name"] ?? ""
    let safe = name.replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
    let html = "<h1>Hello \(safe)</h1>"
    return Response(status: .ok, body: .init(string: html))
}
`
	flows := Analyze(code, "/app/SafeGreetController.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO HTML flow for HTML-escaped value, got %s -> %s (sinkID=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// NEGATIVE: a benign same-suffix constructor `URLResponse(...)` (Foundation,
// not a Vapor HTML response) must NOT match — the `\bResponse\s*\(` pattern's
// word boundary excludes `URLResponse(` (no boundary between L and R).
func TestSwift_VaporResponse_XSS_URLResponse_NoFire(t *testing.T) {
	code := `
import Foundation

func handler(req: Request) -> URLResponse {
    let name = req.query[String.self, at: "name"] ?? ""
    _ = name
    return URLResponse(url: URL(string: "https://x")!, mimeType: nil, expectedContentLength: 0, textEncodingName: nil)
}
`
	flows := Analyze(code, "/app/URLResp.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO HTML flow for benign URLResponse(...), got %s -> %s (sinkID=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
