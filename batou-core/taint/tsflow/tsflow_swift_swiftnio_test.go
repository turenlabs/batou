package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — AsyncHTTPClient SSRF tests (swift-server/async-http-client)
// =========================================================================

func TestSwift_AsyncHTTP_ModernRequest_SSRF(t *testing.T) {
	code := `
import AsyncHTTPClient
import Vapor

func handler(req: Request) async throws -> String {
    let target = req.query["url"]
    var request = HTTPClientRequest(url: target)
    request.method = .GET
    let response = try await HTTPClient.shared.execute(request, timeout: .seconds(30))
    return "\(response.status)"
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for req.query -> HTTPClientRequest(url:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_AsyncHTTP_LegacyRequest_SSRF(t *testing.T) {
	code := `
import AsyncHTTPClient
import Vapor

func handler(req: Request) throws -> String {
    let target = req.query["endpoint"]
    let request = try HTTPClient.Request(url: target, method: .POST)
    return "\(request)"
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for req.query -> HTTPClient.Request(url:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_AsyncHTTP_SharedSingleton_SSRF(t *testing.T) {
	code := `
import AsyncHTTPClient
import Vapor

func handler(req: Request) async throws -> String {
    let target = req.query["u"]
    let response = try await HTTPClient.shared.get(url: target)
    return "\(response)"
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for req.query -> HTTPClient.shared.get(url:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — SwiftNIO NonBlockingFileIO / NIOFileHandle path traversal tests
// =========================================================================

func TestSwift_SwiftNIO_FileIO_OpenFile_PathTraversal(t *testing.T) {
	code := `
import NIOPosix
import Vapor

func handler(req: Request) async throws -> String {
    let filename = req.query["file"]
    let handle = try await req.application.fileio.openFile(path: filename, eventLoop: req.eventLoop).get()
    return "\(handle)"
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for req.query -> fileio.openFile(path:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_SwiftNIO_FileIO_ReadEntireFile_PathTraversal(t *testing.T) {
	code := `
import NIOPosix
import Vapor

func handler(req: Request) async throws -> String {
    let filename = req.query["name"]
    let buffer = try await req.application.fileio.readEntireFile(path: filename, eventLoop: req.eventLoop).get()
    return "\(buffer)"
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for req.query -> fileio.readEntireFile(path:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_SwiftNIO_NIOFileHandle_PathTraversal(t *testing.T) {
	code := `
import NIOPosix
import Vapor

func handler(req: Request) throws -> String {
    let filename = req.query["path"]
    let handle = try NIOFileHandle(path: filename, mode: .read, flags: .default)
    return "\(handle)"
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for req.query -> NIOFileHandle(path:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — Safe cases (should NOT trigger)
// =========================================================================

func TestSwift_AsyncHTTP_HardcodedURL_NoFlow(t *testing.T) {
	code := `
import AsyncHTTPClient

func handler() async throws -> String {
    let request = HTTPClientRequest(url: "https://api.example.com/ping")
    let response = try await HTTPClient.shared.execute(request, timeout: .seconds(30))
    return "\(response.status)"
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("expected NO SSRF flow for hardcoded URL constant, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
