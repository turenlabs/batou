package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C return-value escape/encode sanitizer tests.
//
// All four sanitizers under test follow the args[0]-tainted, return-value
// pattern that the tsflow walker supports: tainted string is the FIRST
// argument and the escaped result is the function's return value, assigned
// to a fresh LHS variable. Functions whose canonical signature places the
// tainted input later (e.g. APR's `apr_pescape_*(pool, str)`, libsodium's
// bin2hex output-buffer style) are intentionally not represented as
// sanitizers because the walker's args[0]-only sanitization model would
// silently no-op them.
//
// Sink choice for each test is constrained by the sink's DangerousArgs:
// `ap_log_rerror`/`ap_log_error`/`ap_log_perror` use [-1] (any arg),
// `getaddrinfo`/`gethostbyname` use [0] (host),
// `mg_send_http_redirect` uses [1] (target),
// `MHD_add_response_header` uses [2] (value).
// Each entry has a negative-control test (sink fires without sanitizer)
// plus a positive sanitization test (sink does not fire with sanitizer).
// =========================================================================

// --- c.glib.strescape (SnkLog) ------------------------------------------

func TestC_GLibStrescape_NegativeControl_LogFires(t *testing.T) {
	code := `
#include <http_log.h>
#include <stdlib.h>

void log_user_input_unsafe(request_rec *r) {
    char *user_input = getenv("USER_INPUT");
    ap_log_rerror("file.c", 42, APLOG_INFO, 0, r, "user said: %s", user_input);
}
`
	flows := Analyze(code, "/app/log_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("negative control: tainted user_input flowing into ap_log_rerror should produce SnkLog flow (without sanitizer)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_GLibStrescape_Sanitizes_Log(t *testing.T) {
	code := `
#include <glib.h>
#include <http_log.h>
#include <stdlib.h>

void log_user_input_safe(request_rec *r) {
    char *user_input = getenv("USER_INPUT");
    char *safe = g_strescape(user_input, NULL);
    ap_log_rerror("file.c", 42, APLOG_INFO, 0, r, "user said: %s", safe);
}
`
	flows := Analyze(code, "/app/log_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("g_strescape() should neutralize log injection — no SnkLog flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- c.openssl.buf2hexstr (SnkLog, SnkHeader) ---------------------------

func TestC_OPENSSLBuf2hexstr_NegativeControl_LogFires(t *testing.T) {
	code := `
#include <http_log.h>
#include <stdlib.h>

void log_binary_unsafe(request_rec *r) {
    char *user_data = getenv("DATA");
    ap_log_rerror("file.c", 42, APLOG_INFO, 0, r, "data: %s", user_data);
}
`
	flows := Analyze(code, "/app/log_bin_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("negative control: tainted user_data flowing into ap_log_rerror should produce SnkLog flow")
	}
}

func TestC_OPENSSLBuf2hexstr_Sanitizes_Log(t *testing.T) {
	code := `
#include <openssl/crypto.h>
#include <http_log.h>
#include <stdlib.h>
#include <string.h>

void log_binary_safe(request_rec *r) {
    char *user_data = getenv("DATA");
    char *hex = OPENSSL_buf2hexstr((const unsigned char *)user_data, strlen(user_data));
    ap_log_rerror("file.c", 42, APLOG_INFO, 0, r, "data: %s", hex);
}
`
	flows := Analyze(code, "/app/log_bin_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("OPENSSL_buf2hexstr() should neutralize log injection — no SnkLog flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_OPENSSLBuf2hexstr_NegativeControl_HeaderFires(t *testing.T) {
	code := `
#include <microhttpd.h>
#include <stdlib.h>

void emit_fingerprint_header_unsafe(struct MHD_Response *resp) {
    char *user_data = getenv("DATA");
    MHD_add_response_header(resp, "X-Fingerprint", user_data);
}
`
	flows := Analyze(code, "/app/hdr_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("negative control: tainted user_data flowing into MHD_add_response_header (args[2]) should produce SnkHeader flow")
	}
}

func TestC_OPENSSLBuf2hexstr_Sanitizes_Header(t *testing.T) {
	code := `
#include <openssl/crypto.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>

void emit_fingerprint_header_safe(struct MHD_Response *resp) {
    char *user_data = getenv("DATA");
    char *hex = OPENSSL_buf2hexstr((const unsigned char *)user_data, strlen(user_data));
    MHD_add_response_header(resp, "X-Fingerprint", hex);
}
`
	flows := Analyze(code, "/app/hdr_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("OPENSSL_buf2hexstr() should neutralize header injection — no SnkHeader flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- c.libxml2.uri_escape (SnkURLFetch, SnkRedirect, SnkHeader) ---------

func TestC_XmlURIEscape_NegativeControl_URLFetchFires(t *testing.T) {
	code := `
#include <netdb.h>
#include <stdlib.h>

void fetch_unsafe(void) {
    char *user_host = getenv("HOST");
    struct addrinfo *result;
    getaddrinfo(user_host, NULL, NULL, &result);
}
`
	flows := Analyze(code, "/app/fetch_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("negative control: tainted user_host flowing into getaddrinfo (args[0]) should produce SnkURLFetch flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_XmlURIEscape_Sanitizes_URLFetch(t *testing.T) {
	code := `
#include <libxml/uri.h>
#include <netdb.h>
#include <stdlib.h>

void fetch_safe(void) {
    char *user_host = getenv("HOST");
    xmlChar *escaped = xmlURIEscape((const xmlChar *)user_host);
    struct addrinfo *result;
    getaddrinfo((const char *)escaped, NULL, NULL, &result);
}
`
	flows := Analyze(code, "/app/fetch_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("xmlURIEscape() should neutralize URL fetch — no SnkURLFetch flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- c.libxml2.uri_escape_str (SnkURLFetch, SnkRedirect, SnkHeader) -----

func TestC_XmlURIEscapeStr_NegativeControl_RedirectFires(t *testing.T) {
	code := `
#include <civetweb.h>
#include <stdlib.h>

void redirect_unsafe(struct mg_connection *conn) {
    char *user_target = getenv("TARGET");
    mg_send_http_redirect(conn, user_target, 302);
}
`
	flows := Analyze(code, "/app/redir_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("negative control: tainted user_target flowing into mg_send_http_redirect (args[1]) should produce SnkRedirect flow")
	}
}

func TestC_XmlURIEscapeStr_Sanitizes_Redirect(t *testing.T) {
	code := `
#include <libxml/uri.h>
#include <civetweb.h>
#include <stdlib.h>

void redirect_safe(struct mg_connection *conn) {
    char *user_target = getenv("TARGET");
    xmlChar *escaped = xmlURIEscapeStr((const xmlChar *)user_target, (const xmlChar *)"/");
    mg_send_http_redirect(conn, (const char *)escaped, 302);
}
`
	flows := Analyze(code, "/app/redir_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("xmlURIEscapeStr() should neutralize redirect — no SnkRedirect flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
