package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Tests for uWebSockets (uWS) C++ request sources.
//
// uNetworking/uWebSockets handlers receive `uWS::HttpRequest *req`. The
// getUrl()/getFullUrl()/getQuery()/getMethod() accessors return
// client-controlled std::string_views. getHeader()/getParameter() were
// already reachable through the generic request-receiver heuristic, but
// getUrl/getFullUrl/getQuery/getMethod were not registered method names,
// so those flows produced no findings before these entries.
//
// Receiver "req" resolves to ObjectType "uWS::HttpRequest" via the
// "request"-substring heuristic in matchesCatalogEntry.
// =========================================================================

func TestCPP_UWS_GetQuery_CommandInjection(t *testing.T) {
	// req->getQuery("cmd") returns a client-controlled query parameter that
	// reaches system() via .c_str() chaining.
	code := `
void handler(uWS::HttpResponse<false>* res, uWS::HttpRequest* req) {
    auto q = req->getQuery("cmd");
    system(q.c_str());
}
`
	flows := Analyze(code, "/app/uws_query.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for req->getQuery() -> system")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_UWS_GetUrl_LogForging(t *testing.T) {
	// req->getUrl() returns the client-controlled request path, logged unsanitized.
	code := `
void handler(uWS::HttpResponse<true>* res, uWS::HttpRequest* req) {
    auto u = req->getUrl();
    spdlog::info(u);
}
`
	flows := Analyze(code, "/app/uws_url.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-forging flow for req->getUrl() -> spdlog::info")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_UWS_GetFullUrl_LogForging(t *testing.T) {
	// req->getFullUrl() returns the client-controlled path plus query string.
	code := `
void handler(uWS::HttpResponse<false>* res, uWS::HttpRequest* req) {
    auto u = req->getFullUrl();
    spdlog::info(u);
}
`
	flows := Analyze(code, "/app/uws_fullurl.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-forging flow for req->getFullUrl() -> spdlog::info")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_UWS_GetMethod_CommandInjection(t *testing.T) {
	// req->getMethod() returns the client-controlled HTTP method string.
	code := `
void handler(uWS::HttpResponse<false>* res, uWS::HttpRequest* req) {
    auto m = req->getMethod();
    system(m.c_str());
}
`
	flows := Analyze(code, "/app/uws_method.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for req->getMethod() -> system")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestCPP_UWS_ConstantPath_NoFlow(t *testing.T) {
	// Negative control: a hardcoded path (no uWS source) must NOT produce a
	// log-forging flow, proving the finding is taint-driven, not pattern-driven.
	code := `
void handler(uWS::HttpResponse<false>* res, uWS::HttpRequest* req) {
    std::string u = "/static/index.html";
    spdlog::info(u);
}
`
	flows := Analyze(code, "/app/uws_const.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("did not expect any log flow for a constant path")
		for i, f := range flows {
			t.Logf("  flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}
