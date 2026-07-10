package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — HTTP header injection tests (CWE-113)
// =========================================================================

func TestSwift_HTTPField_Init_HeaderInjection(t *testing.T) {
	code := `
import Vapor
import HTTPTypes

func handler(req: Request) -> Response {
    let userAgent = req.headers["User-Agent"]
    let field = HTTPField(name: .init("X-Forwarded-Agent")!, value: userAgent)
    var fields = HTTPFields()
    fields.append(field)
    return Response(status: .ok)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for req.headers -> HTTPField(name:value:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_Hummingbird_HeaderFields_Append(t *testing.T) {
	code := `
import Hummingbird
import HTTPTypes

func handler(request: HBRequest) -> HBResponse {
    let origin = request.headers["Origin"]
    var response = HBResponse(status: .ok)
    response.headerFields.append(HTTPField(name: .init("Access-Control-Allow-Origin")!, value: origin))
    return response
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for request.headers -> headerFields.append()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_Header_Sanitized_NewlineFilter(t *testing.T) {
	code := `
import Vapor
import HTTPTypes

func handler(req: Request) -> Response {
    let raw = req.query["value"]
    let safe = raw.filter { $0 != "\r" && $0 != "\n" }
    let field = HTTPField(name: .init("X-Custom")!, value: safe)
    return Response(status: .ok)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Error("expected NO header injection flow when newline characters are filtered")
		}
	}
}

// =========================================================================
// Swift — Insecure deserialization tests (CWE-502)
// =========================================================================

func TestSwift_NSKeyedUnarchiver_TopLevelObject(t *testing.T) {
	code := `
import Foundation

func handler(data: Data) {
    let networkData = URLSession.shared.dataTask(with: url)
    let obj = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(networkData)
    print(obj)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow for network data -> unarchiveTopLevelObjectWithData")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_NSCoder_DecodeObject_Unsafe(t *testing.T) {
	code := `
import Foundation
import Vapor

func handler(req: Request) {
    let key = req.query["field"]
    let obj = unarchiver.decodeObject(forKey: key)
    print(obj)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow for user-controlled key -> decodeObject(forKey:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_NSCoder_DecodeObject_TypeSafe_NoFlow(t *testing.T) {
	code := `
import Foundation

func handler() {
    let safeData = Data("hardcoded".utf8)
    let unarchiver = try NSKeyedUnarchiver(forReadingFrom: safeData)
    let obj = try unarchiver.decodeObject(of: UserProfile.self, forKey: "root")
    print(obj)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Error("expected NO deserialization flow when no taint source is present")
		}
	}
}
