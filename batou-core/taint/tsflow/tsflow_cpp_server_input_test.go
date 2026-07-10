package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Tests for new C++ server-side input sources.
//
// Boost.Beast HTTP request: method_string(), at(field), find(field).
// gRPC ServerContext:        client_metadata(), peer().
//
// The existing cpp.boost.beast.http.request.{body,target,header} entries
// only cover body() and target() in tsflow — the .header entry's MethodName
// "header_field" never matches an actual call method, so at()/find() were
// not flowing. The existing cpp.grpc.request entry uses MethodName
// "ServerContext" which only matches constructor-style calls, so common
// `context->client_metadata()` / `context->peer()` patterns produced no
// flows.
// =========================================================================

func TestCPP_BoostBeast_At_SSRFViaSystem(t *testing.T) {
	// req.at(boost::beast::http::field::host) returns a tainted string_view;
	// the value reaches system() via .c_str() chaining.
	code := `
void handler(boost::beast::http::request<boost::beast::http::string_body>& req) {
    auto host = req.at(boost::beast::http::field::host);
    system(host.c_str());
}
`
	flows := Analyze(code, "/app/beast_at.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for req.at(http::field::host) -> system")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_BoostBeast_MethodString_LogForging(t *testing.T) {
	// req.method_string() returns a string_view of the HTTP verb name,
	// which is client-controlled and reaches a log sink unsanitized.
	code := `
void handler(boost::beast::http::request<boost::beast::http::string_body>& req) {
    auto m = req.method_string();
    spdlog::info(m);
}
`
	flows := Analyze(code, "/app/beast_method.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-forging flow for req.method_string() -> spdlog::info")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_BoostBeast_Find_CommandInjection(t *testing.T) {
	// req.find(http::field::host) returns a tainted iterator; the caller
	// dereferences it->value() to access the user-controlled header value
	// and feeds it to system().
	code := `
void handler(boost::beast::http::request<boost::beast::http::string_body>& req) {
    auto it = req.find(boost::beast::http::field::host);
    std::string val(it->value());
    system(val.c_str());
}
`
	flows := Analyze(code, "/app/beast_find.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for req.find(http::field::host) -> system")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_GRPC_ClientMetadata_LogForging(t *testing.T) {
	// context->client_metadata() returns a tainted multimap; logging an
	// iterator value-view from a multimap entry is a realistic pattern in
	// gRPC handlers that copy headers into log records.
	code := `
void Handler(grpc::ServerContext* context) {
    auto md = context->client_metadata();
    auto it = md.find("authorization");
    spdlog::info(it->second);
}
`
	flows := Analyze(code, "/app/grpc_metadata.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-forging flow for context->client_metadata() -> spdlog::info")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_GRPC_Peer_LogForging(t *testing.T) {
	// context->peer() returns the unauthenticated peer URI string and is
	// commonly logged. Per gRPC docs this string MUST NOT be used for
	// security-related code — log injection is the realistic risk.
	code := `
void Handler(grpc::ServerContext* context) {
    auto p = context->peer();
    spdlog::info(p);
}
`
	flows := Analyze(code, "/app/grpc_peer.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-forging flow for context->peer() -> spdlog::info")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative test: untainted constant string passed to system() should NOT
// produce a command-injection flow even when a Boost.Beast request is in
// scope. Guards against the new patterns over-firing on unrelated code.
func TestCPP_BoostBeast_NoFlowOnConstant(t *testing.T) {
	code := `
void handler(boost::beast::http::request<boost::beast::http::string_body>& req) {
    (void)req;
    system("echo hello");
}
`
	flows := Analyze(code, "/app/beast_negative.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command-injection flow for a constant-string system() call")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}
