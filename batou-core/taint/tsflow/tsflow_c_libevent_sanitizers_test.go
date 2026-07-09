package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// libevent (evhttp) return-value escape sanitizer tests.
//
// libevent already supplies a request source (c.net.evhttp_uri via
// evhttp_request_get_uri); these sanitizers close the output-encoding side
// of the same library. All three follow the args[0]-tainted, return-value
// pattern the tsflow walker supports: the tainted string is the FIRST
// argument and the escaped result is the function's return value, assigned
// to a fresh LHS variable.
//
//   char *evhttp_encode_uri(const char *str)
//   char *evhttp_uriencode(const char *str, ev_ssize_t size, int space_to_plus)
//   char *evhttp_htmlescape(const char *html)
//
// Sink choice is constrained by what actually fires in tsflow:
//   getaddrinfo  -> SnkURLFetch (host at arg[0])
//   mg_http_reply -> SnkHTMLOutput (DangerousArgs [-1], any arg)
// Each entry has a negative-control test (sink fires without the sanitizer)
// plus a positive test (sink does not fire once the sanitizer is applied).
// =========================================================================

// --- c.evhttp.encode_uri (SnkURLFetch / SnkRedirect) --------------------

func TestC_EvhttpEncodeUri_NegativeControl_SSRFFires(t *testing.T) {
	code := `
#include <stdlib.h>
#include <netdb.h>

void resolve_unsafe() {
    char *host = getenv("TARGET_HOST");
    struct addrinfo *res;
    getaddrinfo(host, "80", NULL, &res);
}
`
	flows := Analyze(code, "/app/evhttp_ssrf_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("negative control: tainted host flowing into getaddrinfo should produce SnkURLFetch flow (without sanitizer)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_EvhttpEncodeUri_Sanitizes_SSRF(t *testing.T) {
	code := `
#include <event2/http.h>
#include <stdlib.h>
#include <netdb.h>

void resolve_safe() {
    char *host = getenv("TARGET_HOST");
    char *safe = evhttp_encode_uri(host);
    struct addrinfo *res;
    getaddrinfo(safe, "80", NULL, &res);
}
`
	flows := Analyze(code, "/app/evhttp_ssrf_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("evhttp_encode_uri() should neutralize the SSRF flow — no SnkURLFetch expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- c.evhttp.uriencode (SnkURLFetch / SnkRedirect) ---------------------

func TestC_EvhttpUriencode_NegativeControl_SSRFFires(t *testing.T) {
	code := `
#include <stdlib.h>
#include <netdb.h>

void resolve_unsafe2() {
    char *host = getenv("TARGET_HOST");
    struct addrinfo *res;
    getaddrinfo(host, "443", NULL, &res);
}
`
	flows := Analyze(code, "/app/evhttp_uriencode_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("negative control: tainted host flowing into getaddrinfo should produce SnkURLFetch flow (without sanitizer)")
	}
}

func TestC_EvhttpUriencode_Sanitizes_SSRF(t *testing.T) {
	code := `
#include <event2/http.h>
#include <stdlib.h>
#include <netdb.h>

void resolve_safe2() {
    char *host = getenv("TARGET_HOST");
    char *safe = evhttp_uriencode(host, -1, 0);
    struct addrinfo *res;
    getaddrinfo(safe, "443", NULL, &res);
}
`
	flows := Analyze(code, "/app/evhttp_uriencode_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("evhttp_uriencode() should neutralize the SSRF flow — no SnkURLFetch expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- c.evhttp.htmlescape (SnkHTMLOutput) --------------------------------

func TestC_EvhttpHtmlescape_NegativeControl_XSSFires(t *testing.T) {
	code := `
#include "mongoose.h"
#include <stdlib.h>

void render_unsafe(struct mg_connection *c) {
    char *input = getenv("QUERY_STRING");
    mg_http_reply(c, 200, "Content-Type: text/html\r\n", "<p>%s</p>", input);
}
`
	flows := Analyze(code, "/app/evhttp_xss_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("negative control: tainted input flowing into mg_http_reply should produce SnkHTMLOutput flow (without sanitizer)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_EvhttpHtmlescape_Sanitizes_XSS(t *testing.T) {
	code := `
#include "mongoose.h"
#include <event2/http.h>
#include <stdlib.h>

void render_safe(struct mg_connection *c) {
    char *input = getenv("QUERY_STRING");
    char *safe = evhttp_htmlescape(input);
    mg_http_reply(c, 200, "Content-Type: text/html\r\n", "<p>%s</p>", safe);
}
`
	flows := Analyze(code, "/app/evhttp_xss_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("evhttp_htmlescape() should neutralize the XSS flow — no SnkHTMLOutput expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
