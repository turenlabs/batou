package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// libonion (davidmoreno/onion) HTTP request source tests.
//
// Verifies that taint introduced by onion_request_get_* APIs propagates to
// dangerous sinks already in the C catalog: header injection / open redirect
// (onion_response_set_header), command injection (system/popen), SQLi
// (sqlite3_exec), path traversal (fopen/open), and SSRF (curl_easy_setopt).
// =========================================================================

// onion_request_get_query -> onion_response_set_header (open redirect / CRLF)
func TestC_Onion_GetQuery_ToResponseHeader(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <onion/response.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *next = onion_request_get_query(req, "next");
    onion_response_set_header(res, "Location", next);
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_redirect.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for onion_request_get_query -> onion_response_set_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// onion_request_get_post -> system (command injection)
func TestC_Onion_GetPost_ToSystem(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <stdlib.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *cmd = onion_request_get_post(req, "cmd");
    system(cmd);
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for onion_request_get_post -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// onion_request_get_header -> popen (command injection)
func TestC_Onion_GetHeader_ToPopen(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <stdio.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *agent = onion_request_get_header(req, "User-Agent");
    FILE *f = popen(agent, "r");
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_popen.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for onion_request_get_header -> popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// onion_request_get_cookie -> sqlite3_exec (SQLi)
func TestC_Onion_GetCookie_ToSQLite3Exec(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <sqlite3.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *sid = onion_request_get_cookie(req, "session");
    sqlite3 *db;
    sqlite3_open("data.db", &db);
    sqlite3_exec(db, sid, 0, 0, 0);
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_sqli.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for onion_request_get_cookie -> sqlite3_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// onion_request_get_path -> fopen (path traversal)
func TestC_Onion_GetPath_ToFopen(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <stdio.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *path = onion_request_get_path(req);
    FILE *f = fopen(path, "r");
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_path.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for onion_request_get_path -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// onion_request_get_fullpath -> open (path traversal)
func TestC_Onion_GetFullpath_ToOpen(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <fcntl.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *fp = onion_request_get_fullpath(req);
    int fd = open(fp, 0);
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_open.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for onion_request_get_fullpath -> open")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// onion_request_get_file -> fopen (path traversal via uploaded file path)
func TestC_Onion_GetFile_ToFopen(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <stdio.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *fpath = onion_request_get_file(req, "upload");
    FILE *f = fopen(fpath, "r");
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_upload.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for onion_request_get_file -> fopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// onion_request_get_session -> system (command injection via session value)
func TestC_Onion_GetSession_ToSystem(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <stdlib.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *role = onion_request_get_session(req, "role");
    system(role);
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_session.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for onion_request_get_session -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// onion_request_get_language_code -> system (command injection via Accept-Language)
func TestC_Onion_GetLanguageCode_ToSystem(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <stdlib.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *lang = onion_request_get_language_code(req);
    system(lang);
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_lang.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for onion_request_get_language_code -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// onion_request_get_queryd -> getaddrinfo (SSRF)
func TestC_Onion_GetQueryd_ToGetaddrinfo(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/request.h>
#include <netdb.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    const char *host = onion_request_get_queryd(req, "host", "localhost");
    struct addrinfo *result;
    getaddrinfo(host, NULL, NULL, &result);
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_ssrf.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for onion_request_get_queryd -> getaddrinfo")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative regression: constant string into onion_response_set_header should
// NOT produce a header-injection flow (catches over-broad source matching).
func TestC_Onion_ConstantHeader_NoFlow(t *testing.T) {
	code := `
#include <onion/onion.h>
#include <onion/response.h>

onion_connection_status handler(void *cls, onion_request *req, onion_response *res) {
    onion_response_set_header(res, "X-Static", "constant-value");
    return OCS_PROCESSED;
}
`
	flows := Analyze(code, "/app/onion_static.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("did not expect header-injection flow for constant onion_response_set_header argument")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
