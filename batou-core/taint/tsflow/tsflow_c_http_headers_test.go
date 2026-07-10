package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C HTTP server header injection / open redirect tests
// Covers libmicrohttpd, civetweb, libonion response APIs.
// =========================================================================

// libmicrohttpd: MHD_lookup_connection_value returns tainted query value that
// flows to MHD_add_response_header (Location redirect / CRLF injection).
func TestC_Header_MHD_AddResponseHeader_Location(t *testing.T) {
	code := `
#include <microhttpd.h>
#include <stdio.h>

int handler(void *cls, struct MHD_Connection *conn, const char *url,
            const char *method, const char *version,
            const char *upload_data, size_t *upload_data_size, void **ptr) {
    const char *target = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "next");
    struct MHD_Response *response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Location", target);
    return MHD_queue_response(conn, 302, response);
}
`
	flows := Analyze(code, "/app/mhd_redirect.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for MHD_lookup_connection_value -> MHD_add_response_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// civetweb: mg_response_header_add flags CRLF injection when value is tainted.
func TestC_Header_Civetweb_ResponseHeaderAdd(t *testing.T) {
	code := `
#include <civetweb.h>
#include <stdlib.h>

int handler(struct mg_connection *conn, void *cbdata) {
    char *target = getenv("REDIRECT_TO");
    mg_response_header_start(conn, 302);
    mg_response_header_add(conn, "Location", target, -1);
    mg_response_header_send(conn);
    return 302;
}
`
	flows := Analyze(code, "/app/civetweb_redirect.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getenv -> mg_response_header_add")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// civetweb: mg_response_header_add_lines flags raw header-line CRLF injection.
func TestC_Header_Civetweb_ResponseHeaderAddLines(t *testing.T) {
	code := `
#include <civetweb.h>
#include <stdlib.h>

int handler(struct mg_connection *conn, void *cbdata) {
    char *headers = getenv("EXTRA_HEADERS");
    mg_response_header_start(conn, 200);
    mg_response_header_add_lines(conn, headers);
    mg_response_header_send(conn);
    return 200;
}
`
	flows := Analyze(code, "/app/civetweb_hdrlines.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getenv -> mg_response_header_add_lines")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// civetweb: mg_send_http_redirect is a dedicated open-redirect helper.
func TestC_Redirect_Civetweb_SendHttpRedirect(t *testing.T) {
	code := `
#include <civetweb.h>
#include <stdlib.h>

int handler(struct mg_connection *conn, void *cbdata) {
    char *target = getenv("NEXT_URL");
    mg_send_http_redirect(conn, target, 302);
    return 302;
}
`
	flows := Analyze(code, "/app/civetweb_open_redirect.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for getenv -> mg_send_http_redirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// libonion: onion_response_set_header flags CRLF / open-redirect when value tainted.
func TestC_Header_Onion_ResponseSetHeader(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/response.h>
#include <stdlib.h>

onion_connection_status redirect_handler(void *_, onion_request *req, onion_response *res) {
    char *target = getenv("NEXT");
    onion_response_set_code(res, 302);
    onion_response_set_header(res, "Location", target);
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_redirect.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getenv -> onion_response_set_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: constant header value must not produce a header flow.
func TestC_Header_MHD_ConstantValue_NoFlow(t *testing.T) {
	code := `
#include <microhttpd.h>

int handler(void *cls, struct MHD_Connection *conn) {
    struct MHD_Response *response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Content-Type", "application/json");
    return MHD_queue_response(conn, 200, response);
}
`
	flows := Analyze(code, "/app/mhd_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("unexpected header flow for constant header value")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
