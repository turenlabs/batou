package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — libxml2 XPath injection tests (CWE-643)
// =========================================================================

func TestSwift_Libxml2_XPathEvalExpression_Injection(t *testing.T) {
	code := `
import Foundation
import libxml2
import Vapor

func handler(req: Request, doc: xmlDocPtr) {
    let userQuery = req.query["search"]
    let ctx = xmlXPathNewContext(doc)
    let expr = "//item[@name='" + userQuery + "']"
    let result = xmlXPathEvalExpression(expr, ctx)
    defer { xmlXPathFreeObject(result) }
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for req.query -> xmlXPathEvalExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_Libxml2_XPathEval_Injection(t *testing.T) {
	code := `
import Foundation
import libxml2
import Vapor

func handler(req: Request, ctx: xmlXPathContextPtr) {
    let input = req.query["xpath"]
    let xpath = "/root/users[name='" + input + "']"
    let result = xmlXPathEval(xpath, ctx)
    defer { xmlXPathFreeObject(result) }
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for req.query -> xmlXPathEval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_Libxml2_XPathNodeEval_Injection(t *testing.T) {
	code := `
import Foundation
import libxml2
import Vapor

func handler(req: Request, node: xmlNodePtr, ctx: xmlXPathContextPtr) {
    let query = req.query["node"]
    let expr = "child::" + query
    let result = xmlXPathNodeEval(node, expr, ctx)
    defer { xmlXPathFreeObject(result) }
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for req.query -> xmlXPathNodeEval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — XPath sanitizer tests
// =========================================================================

func TestSwift_Libxml2_XPath_Sanitized_XMLNodeText(t *testing.T) {
	code := `
import Foundation
import Vapor

func handler(req: Request) {
    let userInput = req.query["data"]
    let doc = try XMLDocument(xmlString: "<root/>")
    let textNode = XMLNode(kind: .text, options: [])
    textNode.stringValue = userInput
    doc.rootElement()?.addChild(textNode)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath {
			t.Error("expected NO XPath flow when XMLNode(kind: .text) DOM API is used")
		}
	}
}

// =========================================================================
// Swift — NSAppleScript command injection tests (CWE-78)
// =========================================================================

func TestSwift_NSAppleScript_Init_CommandInjection(t *testing.T) {
	code := `
import Foundation
import Vapor

func handler(req: Request) throws {
    let cmd = req.query["script"]
    let appleScript = NSAppleScript(source: cmd)
    var error: NSDictionary?
    appleScript?.executeAndReturnError(&error)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for req.query -> NSAppleScript(source:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — Trust boundary tests (CWE-501)
// =========================================================================

func TestSwift_UserDefaults_TrustBoundary(t *testing.T) {
	code := `
import Foundation
import Vapor

func handler(req: Request) throws {
    let token = req.query["token"]
    UserDefaults.standard.set(token, forKey: "authToken")
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for req.query -> UserDefaults.standard.set")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

