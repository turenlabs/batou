package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — CocoaLumberjack log-injection tests (CWE-117)
//
// CocoaLumberjack's Swift wrappers (DDLogError, DDLogWarn, DDLogInfo,
// DDLogDebug, DDLogVerbose) are top-level functions, so tainted user input
// passed in the message argument allows log forging (newline injection,
// fake entries) per CWE-117.
// =========================================================================

func TestSwift_CocoaLumberjack_DDLogError_Injection(t *testing.T) {
	code := `
import CocoaLumberjackSwift
import Vapor

func handler(req: Request) {
    let name = req.query["name"]
    DDLogError("User error: \(name)")
}
`
	flows := Analyze(code, "/app/Handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for req.query -> DDLogError")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CocoaLumberjack_DDLogInfo_Injection(t *testing.T) {
	code := `
import CocoaLumberjackSwift
import WebKit

func handler(message: WKScriptMessage) {
    let data = message.body
    DDLogInfo("Received: \(data)")
}
`
	flows := Analyze(code, "/app/Handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for WKScriptMessage.body -> DDLogInfo")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CocoaLumberjack_DDLogWarn_Injection(t *testing.T) {
	code := `
import CocoaLumberjackSwift
import Vapor

func handler(req: Request) {
    let ua = req.headers["User-Agent"]
    DDLogWarn("Suspicious UA: \(ua)")
}
`
	flows := Analyze(code, "/app/Handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for req.headers -> DDLogWarn")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CocoaLumberjack_DDLogDebug_Injection(t *testing.T) {
	code := `
import CocoaLumberjackSwift
import Vapor

func handler(req: Request) {
    let body = req.query["body"]
    DDLogDebug("body=\(body)")
}
`
	flows := Analyze(code, "/app/Handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for req.query -> DDLogDebug")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CocoaLumberjack_DDLogVerbose_Injection(t *testing.T) {
	code := `
import CocoaLumberjackSwift
import Vapor

func handler(req: Request) {
    let input = req.query["q"]
    DDLogVerbose("query=\(input)")
}
`
	flows := Analyze(code, "/app/Handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for req.query -> DDLogVerbose")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — safe case (static string should NOT trigger log-injection finding)
// =========================================================================

func TestSwift_CocoaLumberjack_DDLogInfo_StaticString_NoFlow(t *testing.T) {
	code := `
import CocoaLumberjackSwift

func handler() {
    DDLogInfo("Static message with no tainted data")
}
`
	flows := Analyze(code, "/app/Handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("did not expect log injection flow when message is a static string, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
