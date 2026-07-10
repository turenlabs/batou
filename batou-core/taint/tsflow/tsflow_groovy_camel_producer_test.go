package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Apache Camel ProducerTemplate SSRF sinks added to groovy_sinks.go.
//
// Camel routes a payload to an endpoint identified by a URI string. The URI
// scheme picks the transport: http:/https:/jetty:/netty4-http: are HTTP
// requests (SSRF), exec: shells out (command injection), jdbc: opens a
// database connection (SQL injection), bean:/class: invoke arbitrary Java,
// file:/ftp: read or write files. Tainted input flowing into args[0] of any
// send/request method therefore lets an attacker pick the protocol.
//
// Catalog entries land at receiver names "producerTemplate" and "producer"
// (matched by ObjectType "ProducerTemplate" via tsflow's prefix-abbreviation
// heuristic in matcher.go). Source side uses Spring WebFlux ServerRequest
// (request.bodyToMono / request.queryParam / request.pathVariable) — already
// recognised by groovy_sources.go, no isWebHandlerFunc auto-taint needed.

func TestGroovy_CamelProducerSendBodySSRF(t *testing.T) {
	code := `
def handle(request) {
    def uri = request.bodyToMono(String.class)
    producerTemplate.sendBody(uri, "payload")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerRequest.bodyToMono -> producerTemplate.sendBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_CamelProducerSendBodyAndHeaderSSRF(t *testing.T) {
	code := `
def handle(request) {
    def uri = request.queryParam("uri")
    producerTemplate.sendBodyAndHeader(uri, "payload", "Content-Type", "text/plain")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerRequest.queryParam -> producerTemplate.sendBodyAndHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_CamelProducerSendBodyAndHeadersSSRF(t *testing.T) {
	code := `
def handle(request) {
    def uri = request.pathVariable("endpoint")
    def hdrs = [Accept: "application/json"]
    producerTemplate.sendBodyAndHeaders(uri, "payload", hdrs)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerRequest.pathVariable -> producerTemplate.sendBodyAndHeaders")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_CamelProducerSendBodyAndPropertySSRF(t *testing.T) {
	code := `
def handle(request) {
    def uri = request.bodyToMono(String.class)
    producerTemplate.sendBodyAndProperty(uri, "payload", "CamelTraceId", "x")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerRequest.bodyToMono -> producerTemplate.sendBodyAndProperty")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_CamelProducerRequestBodySSRF(t *testing.T) {
	code := `
def handle(request) {
    def uri = request.bodyToMono(String.class)
    def reply = producerTemplate.requestBody(uri, "payload")
    return reply
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerRequest.bodyToMono -> producerTemplate.requestBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_CamelProducerRequestBodyAndHeaderSSRF(t *testing.T) {
	code := `
def handle(request) {
    def uri = request.queryParam("dest")
    producerTemplate.requestBodyAndHeader(uri, "payload", "X-Tenant", "acme")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerRequest.queryParam -> producerTemplate.requestBodyAndHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_CamelProducerRequestBodyAndHeadersSSRF(t *testing.T) {
	code := `
def handle(request) {
    def uri = request.pathVariable("dest")
    def hdrs = [X: "y"]
    producerTemplate.requestBodyAndHeaders(uri, "payload", hdrs)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerRequest.pathVariable -> producerTemplate.requestBodyAndHeaders")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_CamelProducerAsyncSendBodySSRF(t *testing.T) {
	code := `
def handle(request) {
    def uri = request.bodyToMono(String.class)
    producerTemplate.asyncSendBody(uri, "payload")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerRequest.bodyToMono -> producerTemplate.asyncSendBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_CamelProducerAsyncRequestBodySSRF(t *testing.T) {
	code := `
def handle(request) {
    def uri = request.bodyToMono(String.class)
    def fut = producerTemplate.asyncRequestBody(uri, "payload")
    return fut
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ServerRequest.bodyToMono -> producerTemplate.asyncRequestBody")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: a constant endpoint URI must NOT produce a user-input SSRF
// flow. This proves the new ProducerTemplate sinks don't introduce over-broad
// matching when the first argument is a literal.
func TestGroovy_CamelProducerNoFlowOnConstantUri(t *testing.T) {
	code := `
def handle() {
    def safe = "direct:internal"
    producerTemplate.sendBody(safe, "payload")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Source.Category == taint.SrcUserInput && f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("unexpected user-input SSRF flow on constant URI: source=%s sink=%s",
				f.Source.ID, f.Sink.ID)
		}
	}
}
