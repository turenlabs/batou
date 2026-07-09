package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — Vapor Client / AsyncHTTPClient instance / WebSocket.connect SSRF
// =========================================================================
//
// Three new SSRF sinks (CWE-918) extending Swift's outbound HTTP coverage:
//
//   1. swift.vapor.client.request       — req.client / app.client.{get,post,put,delete,patch,send}
//   2. swift.asynchttp.client.request   — httpClient.{get,post,put,delete,patch,head}(url:)
//   3. swift.vapor.websocket.connect    — WebSocket.connect(to:on:onUpgrade:)
//
// Receiver-name matching:
//   - "Vapor.Client":   lastPart "client" → matches receivers `client`,
//                       `req.client`, `app.client` (via tsflow matcher's
//                       lastPart/recvLast heuristic).
//   - "HTTPClient":     lastPart "httpclient" → matches receiver `httpClient`
//                       (NOT plain `client`; different lastPart from the
//                       Vapor.Client entry, no overlap).
//   - "WebSocket":      lastPart "websocket" → matches static `WebSocket.connect`.
//
// Tests pass tainted variables directly to sinks (the pattern used by the
// existing tsflow_swift_swiftnio_test.go SSRF tests). Inline / nested
// constructors before the sink reduce taint propagation in the Swift walker;
// the canonical SSRF pattern in real Vapor handlers is to extract user input
// to a local then pass that local, which IS what these tests model.

// ---------- Vapor Client (req.client / app.client) ------------------------

// req.client.get with tainted URL — canonical SSRF.
func TestSwift_VaporClient_Get_TaintedURL(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) async throws -> ClientResponse {
    let target = req.query["target"]
    let response = try await req.client.get(url: target)
    return response
}
`
	flows := Analyze(code, "/app/Handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> req.client.get(url:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// req.client.post with tainted URL.
func TestSwift_VaporClient_Post_TaintedURL(t *testing.T) {
	code := `
import Vapor

func proxy(req: Request) async throws -> ClientResponse {
    let dest = req.query["dest"]
    let response = try await req.client.post(dest)
    return response
}
`
	flows := Analyze(code, "/app/Proxy.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> req.client.post(dest); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// app.client.delete — application-scope client with tainted URL.
func TestSwift_VaporClient_AppClientDelete_TaintedURL(t *testing.T) {
	code := `
import Vapor

func purge(req: Request, app: Application) async throws {
    let id = req.query["id"]
    _ = try await app.client.delete(id)
}
`
	flows := Analyze(code, "/app/Purge.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> app.client.delete(id); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// req.client.patch — covers the patch verb specifically.
func TestSwift_VaporClient_Patch_TaintedURL(t *testing.T) {
	code := `
import Vapor

func patchUser(req: Request) async throws -> ClientResponse {
    let upstream = req.query["upstream"]
    let response = try await req.client.patch(upstream)
    return response
}
`
	flows := Analyze(code, "/app/Patch.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> req.client.patch(upstream); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// req.client.send with tainted URL — flowing through ClientRequest constructor.
func TestSwift_VaporClient_Send_TaintedURL(t *testing.T) {
	code := `
import Vapor

func relay(req: Request) async throws -> ClientResponse {
    let dest = req.query["dest"] ?? ""
    let clientReq = ClientRequest(method: .GET, url: URI(string: dest)!, headers: [:], body: nil)
    return try await req.client.send(clientReq)
}
`
	flows := Analyze(code, "/app/Relay.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> req.client.send(ClientRequest); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative: constant URL → no swift.vapor.client.request flow.
func TestSwift_VaporClient_ConstantURL_NoFlow(t *testing.T) {
	code := `
import Vapor

func health(req: Request) async throws -> ClientResponse {
    _ = req.query["target"]
    let response = try await req.client.get("https://api.example.com/healthz")
    return response
}
`
	flows := Analyze(code, "/app/Health.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.ID == "swift.vapor.client.request" {
			t.Errorf("expected no swift.vapor.client.request flow on constant URL, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// ---------- AsyncHTTPClient instance convenience methods ------------------

// httpClient.get(url: tainted) — instance (NOT shared) convenience method.
func TestSwift_AsyncHTTPInstance_Get_TaintedURL(t *testing.T) {
	code := `
import AsyncHTTPClient
import Vapor

func fetch(req: Request) async throws {
    let target = req.query["url"]
    let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
    _ = try await httpClient.get(url: target)
}
`
	flows := Analyze(code, "/app/Fetch.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> httpClient.get(url:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// httpClient.post(url: tainted) — covers POST verb on instance.
func TestSwift_AsyncHTTPInstance_Post_TaintedURL(t *testing.T) {
	code := `
import AsyncHTTPClient
import Vapor

func push(req: Request) async throws {
    let upstream = req.query["upstream"]
    let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
    _ = try await httpClient.post(url: upstream)
}
`
	flows := Analyze(code, "/app/Push.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> httpClient.post(url:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative: constant URL on httpClient.get — no flow.
func TestSwift_AsyncHTTPInstance_ConstantURL_NoFlow(t *testing.T) {
	code := `
import AsyncHTTPClient
import Vapor

func ping(req: Request) async throws {
    _ = req.query["target"]
    let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
    _ = try await httpClient.get(url: "https://api.example.com/ping")
}
`
	flows := Analyze(code, "/app/Ping.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.ID == "swift.asynchttp.client.request" {
			t.Errorf("expected no swift.asynchttp.client.request flow on constant URL, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// ---------- Vapor / SwiftNIO WebSocket.connect outbound SSRF -------------

// WebSocket.connect(to: tainted, ...) with tainted URL string.
func TestSwift_VaporWebSocket_Connect_TaintedURL(t *testing.T) {
	code := `
import Vapor
import WebSocketKit

func bridge(req: Request) async throws {
    let upstream = req.query["upstream"]
    try await WebSocket.connect(to: upstream, on: req.eventLoop) { ws in
        ws.send("hello")
    }.get()
}
`
	flows := Analyze(code, "/app/Bridge.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Errorf("expected SSRF flow for req.query -> WebSocket.connect(to:); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative: constant URL on WebSocket.connect — no flow.
func TestSwift_VaporWebSocket_Connect_ConstantURL_NoFlow(t *testing.T) {
	code := `
import Vapor
import WebSocketKit

func bridge(req: Request) async throws {
    _ = req.query["upstream"]
    try await WebSocket.connect(to: "wss://api.example.com/ws", on: req.eventLoop) { ws in
        ws.send("hello")
    }.get()
}
`
	flows := Analyze(code, "/app/BridgeConst.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.ID == "swift.vapor.websocket.connect" {
			t.Errorf("expected no swift.vapor.websocket.connect flow on constant URL, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
