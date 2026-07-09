package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — WKScriptMessage (JavaScript bridge) source tests
// =========================================================================

func TestSwift_WKScriptMessage_Body_LogInjection(t *testing.T) {
	code := `
import WebKit
import Foundation

func handler(message: WKScriptMessage) {
    let data = message.body
    NSLog(data)
}
`
	flows := Analyze(code, "/app/Handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for WKScriptMessage.body -> NSLog")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_WKScriptMessage_Body_SQLInjection(t *testing.T) {
	code := `
import WebKit
import SQLite3

func handler(message: WKScriptMessage, db: OpaquePointer?) {
    let input = message.body
    sqlite3_exec(db, "INSERT INTO logs VALUES ('" + input + "')", nil, nil, nil)
}
`
	flows := Analyze(code, "/app/Handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for WKScriptMessage.body -> sqlite3_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — AVCapture QR/barcode scanning source tests
// =========================================================================

func TestSwift_AVCapture_Metadata_LogInjection(t *testing.T) {
	code := `
import AVFoundation
import Foundation

func processCode(readable: AVMetadataMachineReadableCodeObject) {
    let scanned = readable.stringValue
    NSLog(scanned)
}
`
	flows := Analyze(code, "/app/Scanner.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for AVMetadataMachineReadableCodeObject.stringValue -> NSLog")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — NSItemProvider share extension source tests
// =========================================================================

func TestSwift_NSItemProvider_LoadItem_LogInjection(t *testing.T) {
	code := `
import Foundation

func handleItem(provider: NSItemProvider) {
    let text = provider.loadItem(forTypeIdentifier: "public.plain-text", options: nil)
    NSLog(text)
}
`
	flows := Analyze(code, "/app/ShareHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for NSItemProvider.loadItem -> NSLog")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — HTTP response headers source tests
// =========================================================================

func TestSwift_URLResponse_AllHeaderFields_LogInjection(t *testing.T) {
	code := `
import Foundation

func handleResponse(response: HTTPURLResponse) {
    let server = response.allHeaderFields["Server"]
    NSLog(server)
}
`
	flows := Analyze(code, "/app/Network.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for allHeaderFields -> NSLog")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — APNs content.userInfo source tests
// =========================================================================

func TestSwift_APNsContent_UserInfo_LogInjection(t *testing.T) {
	code := `
import Foundation
import UserNotifications

func handleNotification(content: UNNotificationContent) {
    let payload = content.userInfo
    NSLog(payload)
}
`
	flows := Analyze(code, "/app/NotifHandler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for UNNotificationContent.userInfo -> NSLog")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — UUID sanitizer tests
// =========================================================================

func TestSwift_UUID_Sanitized_SQLInjection(t *testing.T) {
	code := `
import Foundation
import SQLite3

func lookupUser(input: String, db: OpaquePointer?) {
    guard let userId = UUID(uuidString: input) else { return }
    sqlite3_exec(db, "SELECT * FROM users WHERE id = '" + userId.uuidString + "'", nil, nil, nil)
}
`
	flows := Analyze(code, "/app/Lookup.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when UUID(uuidString:) sanitizes input")
		}
	}
}
