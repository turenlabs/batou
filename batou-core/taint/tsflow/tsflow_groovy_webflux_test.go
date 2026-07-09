package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Spring WebFlux ServerRequest sources added to groovy_sources.go.
// ServerRequest is the request abstraction in Spring WebFlux functional and
// annotated routing — used by Groovy/Spring Boot reactive web apps.

func TestGroovy_WebFluxBodyToMonoToSQLInjection(t *testing.T) {
	code := `
def handle(request) {
    def body = request.bodyToMono(String.class)
    sql.execute("INSERT INTO audit VALUES ('" + body + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ServerRequest.bodyToMono -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_WebFluxBodyToFluxToCommand(t *testing.T) {
	code := `
def handle(request) {
    def items = request.bodyToFlux(String.class)
    Runtime.getRuntime().exec("notify " + items)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ServerRequest.bodyToFlux -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_WebFluxQueryParamToSQLInjection(t *testing.T) {
	code := `
def handle(request) {
    def id = request.queryParam("id")
    sql.execute("SELECT * FROM users WHERE id = '" + id + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ServerRequest.queryParam -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_WebFluxQueryParamsToSQLInjection(t *testing.T) {
	code := `
def handle(req) {
    def params = req.queryParams()
    sql.execute("SELECT * FROM logs WHERE filter = '" + params + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ServerRequest.queryParams -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_WebFluxPathVariableToCommand(t *testing.T) {
	code := `
def handle(request) {
    def name = request.pathVariable("name")
    Runtime.getRuntime().exec("ping " + name)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ServerRequest.pathVariable -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_WebFluxPathVariablesToSQLInjection(t *testing.T) {
	code := `
def handle(request) {
    def vars = request.pathVariables()
    sql.execute("UPDATE users SET role='admin' WHERE id = '" + vars + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ServerRequest.pathVariables -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_WebFluxHeadersToSQLInjection(t *testing.T) {
	code := `
def handle(request) {
    def hdrs = request.headers()
    sql.execute("INSERT INTO sessions VALUES ('" + hdrs + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ServerRequest.headers -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_WebFluxCookiesToCommand(t *testing.T) {
	code := `
def handle(request) {
    def jar = request.cookies()
    Runtime.getRuntime().exec("logger " + jar)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ServerRequest.cookies -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_WebFluxFormDataToSQLInjection(t *testing.T) {
	code := `
def handle(request) {
    def form = request.formData()
    sql.execute("INSERT INTO submissions VALUES ('" + form + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ServerRequest.formData -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_WebFluxMultipartDataToCommand(t *testing.T) {
	code := `
def handle(request) {
    def parts = request.multipartData()
    Runtime.getRuntime().exec("process " + parts)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ServerRequest.multipartData -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: a constant string passed to sql.execute must NOT be reported,
// proving the new ServerRequest sources don't introduce over-broad matching.
func TestGroovy_WebFluxNoFlowOnConstant(t *testing.T) {
	code := `
def handle() {
    def safe = "literal-id"
    sql.execute("SELECT * FROM users WHERE id = '" + safe + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Source.Category == taint.SrcUserInput && f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected user-input flow on constant string: source=%s sink=%s",
				f.Source.ID, f.Sink.ID)
		}
	}
}
