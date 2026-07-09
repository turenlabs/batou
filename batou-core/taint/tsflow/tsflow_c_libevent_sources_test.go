package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// libevent (evhttp) request/URI read sources.
// Verifies that user-controlled data returned by the evhttp accessor family
// propagates taint into a downstream command-execution sink. Flows go
// directly into system() because the C tsflow walker does not model taint
// propagation through snprintf-style formatting.
// =========================================================================

// evhttp_find_header returns a header / query-argument value chosen by key.
func TestC_Libevent_FindHeader_Command(t *testing.T) {
	code := `
#include <event2/http.h>
#include <stdlib.h>

void handler(struct evhttp_request *req, void *arg) {
    struct evkeyvalq *headers = evhttp_request_get_input_headers(req);
    const char *host = evhttp_find_header(headers, "X-Forwarded-Host");
    system(host);
}
`
	flows := Analyze(code, "/app/evhttp_find.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for evhttp_find_header -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// evhttp_request_get_host returns the request Host header value.
func TestC_Libevent_RequestHost_Command(t *testing.T) {
	code := `
#include <event2/http.h>
#include <stdlib.h>

void handler(struct evhttp_request *req, void *arg) {
    const char *host = evhttp_request_get_host(req);
    system(host);
}
`
	flows := Analyze(code, "/app/evhttp_host.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for evhttp_request_get_host -> system")
	}
}

// The parsed-URI component accessors each return a tainted substring of the
// request URI.
func TestC_Libevent_UriComponents_Command(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"query", "evhttp_uri_get_query(uri)"},
		{"path", "evhttp_uri_get_path(uri)"},
		{"host", "evhttp_uri_get_host(uri)"},
		{"userinfo", "evhttp_uri_get_userinfo(uri)"},
		{"fragment", "evhttp_uri_get_fragment(uri)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
#include <event2/http.h>
#include <stdlib.h>

void handler(struct evhttp_uri *uri) {
    const char *part = ` + tc.call + `;
    system(part);
}
`
			flows := Analyze(code, "/app/evhttp_uri_"+tc.name+".c", rules.LangC)
			if !hasTaintFlow(flows, taint.SnkCommand) {
				t.Errorf("expected command-injection flow for evhttp_uri_get_%s -> system", tc.name)
			}
		})
	}
}

// evhttp_decode_uri / evhttp_uridecode return a decoded copy of a
// user-supplied URI-encoded string.
func TestC_Libevent_DecodeUri_Command(t *testing.T) {
	for _, fn := range []string{"evhttp_decode_uri(raw)", "evhttp_uridecode(raw, 1, NULL)"} {
		code := `
#include <event2/http.h>
#include <stdlib.h>

void handler(const char *raw) {
    char *dec = ` + fn + `;
    system(dec);
}
`
		flows := Analyze(code, "/app/evhttp_decode.c", rules.LangC)
		if !hasTaintFlow(flows, taint.SnkCommand) {
			t.Errorf("expected command-injection flow for %s -> system", fn)
		}
	}
}

// Negative control: no libevent source feeds the sink, so a constant command
// must not produce a flow.
func TestC_Libevent_ConstantNoFlow(t *testing.T) {
	code := `
#include <event2/http.h>
#include <stdlib.h>

void handler(void) {
    system("ls -la");
}
`
	flows := Analyze(code, "/app/evhttp_const.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command flow when no libevent source feeds the sink")
	}
}
