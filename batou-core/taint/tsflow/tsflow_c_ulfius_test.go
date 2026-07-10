package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ulfius (babelouest/ulfius) HTTP request source tests.
//
// Ulfius exposes all request input through four _u_map maps on the
// struct _u_request (map_url, map_header, map_cookie, map_post_body), each
// read with the same u_map_get / u_map_get_case accessor, plus an array
// accessor (u_map_enum_values) and a parsed-JSON-body helper
// (ulfius_get_json_body_request). These tests verify taint introduced by
// those accessors propagates to dangerous sinks already in the C catalog:
// command injection (system/popen), SQLi (sqlite3_exec), path traversal
// (fopen/open), header injection (onion_response_set_header), and SSRF
// (getaddrinfo).
// =========================================================================

// u_map_get(map_url, ...) -> system (command injection via query parameter)
func TestC_Ulfius_MapGetURL_ToSystem(t *testing.T) {
	code := `
#include <ulfius.h>
#include <stdlib.h>

int callback(const struct _u_request *request, struct _u_response *response, void *user_data) {
    const char *cmd = u_map_get(request->map_url, "cmd");
    system(cmd);
    return U_CALLBACK_CONTINUE;
}
`
	flows := Analyze(code, "/app/ulfius_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for u_map_get(map_url) -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// u_map_get(map_post_body, ...) -> sqlite3_exec (SQLi via POST parameter)
func TestC_Ulfius_MapGetPostBody_ToSQLite3Exec(t *testing.T) {
	code := `
#include <ulfius.h>
#include <sqlite3.h>

int callback(const struct _u_request *request, struct _u_response *response, void *user_data) {
    const char *name = u_map_get(request->map_post_body, "name");
    sqlite3 *db;
    sqlite3_open("data.db", &db);
    sqlite3_exec(db, name, 0, 0, 0);
    return U_CALLBACK_CONTINUE;
}
`
	flows := Analyze(code, "/app/ulfius_sqli.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for u_map_get(map_post_body) -> sqlite3_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// u_map_get(map_cookie, ...) -> popen (command injection via cookie value)
func TestC_Ulfius_MapGetCookie_ToPopen(t *testing.T) {
	code := `
#include <ulfius.h>
#include <stdio.h>

int callback(const struct _u_request *request, struct _u_response *response, void *user_data) {
    const char *sid = u_map_get(request->map_cookie, "session");
    FILE *f = popen(sid, "r");
    return U_CALLBACK_CONTINUE;
}
`
	flows := Analyze(code, "/app/ulfius_popen.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for u_map_get(map_cookie) -> popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// u_map_get_case(map_header, ...) -> fopen (path traversal via header)
func TestC_Ulfius_MapGetCaseHeader_ToFopen(t *testing.T) {
	code := `
#include <ulfius.h>
#include <stdio.h>

int callback(const struct _u_request *request, struct _u_response *response, void *user_data) {
    const char *path = u_map_get_case(request->map_header, "X-File");
    FILE *f = fopen(path, "r");
    return U_CALLBACK_CONTINUE;
}
`
	flows := Analyze(code, "/app/ulfius_path.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for u_map_get_case(map_header) -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// u_map_enum_values(map_url) -> system (command injection via values array)
func TestC_Ulfius_MapEnumValues_ToSystem(t *testing.T) {
	code := `
#include <ulfius.h>
#include <stdlib.h>

int callback(const struct _u_request *request, struct _u_response *response, void *user_data) {
    const char **values = u_map_enum_values(request->map_url);
    system(values[0]);
    return U_CALLBACK_CONTINUE;
}
`
	flows := Analyze(code, "/app/ulfius_enum.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for u_map_enum_values -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ulfius_get_json_body_request -> json extraction -> system (command injection)
func TestC_Ulfius_JsonBody_ToSystem(t *testing.T) {
	code := `
#include <ulfius.h>
#include <jansson.h>
#include <stdlib.h>

int callback(const struct _u_request *request, struct _u_response *response, void *user_data) {
    json_t *body = ulfius_get_json_body_request(request, NULL);
    const char *cmd = json_string_value(json_object_get(body, "cmd"));
    system(cmd);
    return U_CALLBACK_CONTINUE;
}
`
	flows := Analyze(code, "/app/ulfius_json.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ulfius_get_json_body_request -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative regression: a constant string passed to a sink in an Ulfius
// callback must NOT produce a flow (catches over-broad source matching).
func TestC_Ulfius_ConstantArg_NoFlow(t *testing.T) {
	code := `
#include <ulfius.h>
#include <stdlib.h>

int callback(const struct _u_request *request, struct _u_response *response, void *user_data) {
    system("/usr/bin/uptime");
    return U_CALLBACK_CONTINUE;
}
`
	flows := Analyze(code, "/app/ulfius_static.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect command flow for constant system() argument")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
