package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// libwebsockets (LWS) HTTP request data source tests.
// LWS is the dominant C/C++ WebSocket / embedded HTTP server library
// (warmcat/libwebsockets). lws_hdr_simple_ptr and lws_get_urlarg_by_name
// each return a const char * into the request — fully attacker-controlled.
// =========================================================================

// lws_hdr_simple_ptr returns a pointer into a request header -> system().
func TestC_LWS_HdrSimplePtr_System(t *testing.T) {
	code := `
#include <libwebsockets.h>
#include <stdlib.h>

int handler(struct lws *wsi) {
    const char *input = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_USER_AGENT);
    system(input);
    return 0;
}
`
	flows := Analyze(code, "/app/lws_hdr_simple_ptr.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for lws_hdr_simple_ptr -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// lws_hdr_simple_ptr -> popen() (alternate command-injection sink).
func TestC_LWS_HdrSimplePtr_Popen(t *testing.T) {
	code := `
#include <libwebsockets.h>
#include <stdio.h>

int handler(struct lws *wsi) {
    const char *input = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_REFERER);
    FILE *fp = popen(input, "r");
    if (fp) pclose(fp);
    return 0;
}
`
	flows := Analyze(code, "/app/lws_hdr_simple_ptr_popen.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for lws_hdr_simple_ptr -> popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// lws_get_urlarg_by_name returns pointer into URL query value -> sqlite3_exec.
func TestC_LWS_GetUrlargByName_SQLite(t *testing.T) {
	code := `
#include <libwebsockets.h>
#include <sqlite3.h>

int handler(struct lws *wsi, sqlite3 *db) {
    char buf[256];
    const char *input = lws_get_urlarg_by_name(wsi, "id", buf, sizeof(buf));
    sqlite3_exec(db, input, 0, 0, 0);
    return 0;
}
`
	flows := Analyze(code, "/app/lws_urlarg.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for lws_get_urlarg_by_name -> sqlite3_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// lws_get_urlarg_by_name -> system() (command-injection variant).
func TestC_LWS_GetUrlargByName_System(t *testing.T) {
	code := `
#include <libwebsockets.h>
#include <stdlib.h>

int handler(struct lws *wsi) {
    char buf[256];
    const char *input = lws_get_urlarg_by_name(wsi, "host", buf, sizeof(buf));
    system(input);
    return 0;
}
`
	flows := Analyze(code, "/app/lws_urlarg_system.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for lws_get_urlarg_by_name -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: a constant string passed to system() must NOT produce a flow,
// guarding against the LWS source patterns being over-broad.
func TestC_LWS_NoFlowOnConstantSystem(t *testing.T) {
	code := `
#include <stdlib.h>

int handler(void) {
    system("ls -la /tmp");
    return 0;
}
`
	flows := Analyze(code, "/app/lws_const.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO command-injection flow on constant string")
		for _, f := range flows {
			t.Logf("  spurious flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
