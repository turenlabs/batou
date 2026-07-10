package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for undici HTTP-client SSRF sinks (CWE-918).
//
// undici is the Node.js built-in HTTP/1.1 client (Node 18+, the engine behind
// global fetch). Each top-level function takes a URL/origin as its first arg;
// when that URL is built from user input, the call becomes an SSRF gadget.
//
// Receiver scoping: every entry sets ObjectType: "undici", so destructured
// imports (`import { request } from 'undici'; request(url)`) intentionally
// fall through to the existing js.request.ssrf catch-all rather than
// double-firing. The qualified `undici.method(...)` form below resolves to
// the new entries because they are placed before js.request.ssrf in the
// catalog slice and matchSinkCall returns the first matching entry.

// --- js.undici.request: positive flow ---

func TestJS_Undici_Request_SSRF(t *testing.T) {
	code := `
function proxy(req, res) {
    const target = req.query.target;
    undici.request("http://" + target + "/api/v1/data");
}
`
	flows := Analyze(code, "/app/routes/proxy.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.undici.request") {
		t.Error("expected js.undici.request flow from req.query -> undici.request()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.undici.fetch: positive flow ---

func TestJS_Undici_Fetch_SSRF(t *testing.T) {
	code := `
function passthrough(req, res) {
    const host = req.body.host;
    undici.fetch("https://" + host + "/v1/me");
}
`
	flows := Analyze(code, "/app/routes/passthrough.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.undici.fetch") {
		t.Error("expected js.undici.fetch flow from req.body -> undici.fetch()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.undici.stream: positive flow ---

func TestJS_Undici_Stream_SSRF(t *testing.T) {
	code := `
function streamProxy(req, res) {
    const upstream = req.query.upstream;
    undici.stream("http://" + upstream + "/file", { method: "GET" }, ({ statusCode }) => res);
}
`
	flows := Analyze(code, "/app/routes/stream.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.undici.stream") {
		t.Error("expected js.undici.stream flow from req.query -> undici.stream()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.undici.pipeline: positive flow ---

func TestJS_Undici_Pipeline_SSRF(t *testing.T) {
	code := `
function pipelineProxy(req, res) {
    const dest = req.body.dest;
    undici.pipeline("http://" + dest + "/transform", {}, ({ body }) => body);
}
`
	flows := Analyze(code, "/app/routes/pipeline.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.undici.pipeline") {
		t.Error("expected js.undici.pipeline flow from req.body -> undici.pipeline()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.undici.connect: positive flow (HTTP CONNECT tunnel) ---

func TestJS_Undici_Connect_SSRF(t *testing.T) {
	code := `
function tunnel(req, res) {
    const host = req.query.host;
    undici.connect("http://" + host + ":8443/");
}
`
	flows := Analyze(code, "/app/routes/tunnel.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.undici.connect") {
		t.Error("expected js.undici.connect flow from req.query -> undici.connect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.undici.upgrade: positive flow (HTTP/1.1 Upgrade) ---

func TestJS_Undici_Upgrade_SSRF(t *testing.T) {
	code := `
function upgradeWS(req, res) {
    const target = req.body.target;
    undici.upgrade("http://" + target + "/ws", { protocol: "websocket" });
}
`
	flows := Analyze(code, "/app/routes/upgrade.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.undici.upgrade") {
		t.Error("expected js.undici.upgrade flow from req.body -> undici.upgrade()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.undici.client.new: positive flow (constructor takes base origin) ---

func TestJS_Undici_Client_New_SSRF(t *testing.T) {
	code := `
function buildClient(req, res) {
    const origin = req.query.origin;
    const c = new undici.Client("http://" + origin);
    c.request({ path: "/" });
}
`
	flows := Analyze(code, "/app/routes/client.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.undici.client.new") {
		t.Error("expected js.undici.client.new flow from req.query -> new undici.Client()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- js.undici.pool.new: positive flow (constructor takes base origin) ---

func TestJS_Undici_Pool_New_SSRF(t *testing.T) {
	code := `
function buildPool(req, res) {
    const origin = req.body.origin;
    const p = new undici.Pool("https://" + origin, { connections: 10 });
    p.request({ path: "/me" });
}
`
	flows := Analyze(code, "/app/routes/pool.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.undici.pool.new") {
		t.Error("expected js.undici.pool.new flow from req.body -> new undici.Pool()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: literal hardcoded URL — no flow expected ---

func TestJS_Undici_Request_LiteralURL_NoFlow(t *testing.T) {
	code := `
function healthcheck(req, res) {
    undici.request("https://api.internal.svc/health");
    res.send("ok");
}
`
	flows := Analyze(code, "/app/routes/health.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.undici.request") {
		t.Error("expected NO js.undici.request flow for literal hardcoded URL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: bare destructured request() — should hit js.request.ssrf,
// NOT the undici-scoped sinks (verifies receiver scoping doesn't false-fire). ---

func TestJS_Undici_DestructuredRequest_ScopedOut(t *testing.T) {
	code := `
function passthrough(req, res) {
    const target = req.query.target;
    request("http://" + target + "/data");
}
`
	flows := Analyze(code, "/app/routes/destructured.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.undici.request") {
		t.Error("expected NO js.undici.request flow for destructured bare request() — must scope to undici.* receiver")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
