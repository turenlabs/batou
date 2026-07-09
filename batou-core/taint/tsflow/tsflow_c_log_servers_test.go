package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ==========================================================================
// C server-logging log injection tests (CWE-117)
// Covers: Apache httpd (ap_log_error/rerror/perror), nginx (ngx_log_error/debug),
// zlog, log4c.
// ==========================================================================

func TestC_ApLogError_Tainted(t *testing.T) {
	code := `
#include <http_log.h>
#include <stdlib.h>

void handle(server_rec *s) {
    char *user = getenv("REMOTE_USER");
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "login attempt: %s", user);
}
`
	flows := Analyze(code, "/app/mod_example.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> ap_log_error")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_ApLogRerror_Tainted(t *testing.T) {
	code := `
#include <http_log.h>
#include <stdlib.h>

void handle_request(request_rec *r) {
    char *ua = getenv("HTTP_USER_AGENT");
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "ua=%s", ua);
}
`
	flows := Analyze(code, "/app/mod_example.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> ap_log_rerror")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_ApLogPerror_Tainted(t *testing.T) {
	code := `
#include <http_log.h>
#include <stdlib.h>

void cleanup(apr_pool_t *p) {
    char *note = getenv("CLEANUP_NOTE");
    ap_log_perror(APLOG_MARK, APLOG_INFO, 0, p, "note=%s", note);
}
`
	flows := Analyze(code, "/app/mod_example.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> ap_log_perror")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_NgxLogError_Tainted(t *testing.T) {
	code := `
#include <ngx_core.h>
#include <stdlib.h>

void on_request(ngx_log_t *log) {
    char *path = getenv("REQUEST_URI");
    ngx_log_error(NGX_LOG_ERR, log, 0, "bad uri: %s", path);
}
`
	flows := Analyze(code, "/app/ngx_module.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> ngx_log_error")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_NgxLogDebug_Tainted(t *testing.T) {
	code := `
#include <ngx_core.h>
#include <stdlib.h>

void trace(ngx_log_t *log) {
    char *id = getenv("TRACE_ID");
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "tid=%s", id);
}
`
	flows := Analyze(code, "/app/ngx_module.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> ngx_log_debug1")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_ZlogInfo_Tainted(t *testing.T) {
	code := `
#include <zlog.h>
#include <stdlib.h>

void log_request(zlog_category_t *cat) {
    char *user = getenv("USER");
    zlog_info(cat, "login: %s", user);
}
`
	flows := Analyze(code, "/app/server.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> zlog_info")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_ZlogError_Tainted(t *testing.T) {
	code := `
#include <zlog.h>
#include <stdlib.h>

void log_failure(zlog_category_t *cat) {
    char *err = getenv("ERR_MSG");
    zlog_error(cat, "failure: %s", err);
}
`
	flows := Analyze(code, "/app/server.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> zlog_error")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Log4cCategoryLog_Tainted(t *testing.T) {
	code := `
#include <log4c.h>
#include <stdlib.h>

void emit(log4c_category_t *cat) {
    char *msg = getenv("MSG");
    log4c_category_log(cat, LOG4C_PRIORITY_INFO, "got %s", msg);
}
`
	flows := Analyze(code, "/app/server.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getenv -> log4c_category_log")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe fixtures: no tainted data flowing into loggers — should produce no flows.

func TestC_ApLogError_Safe(t *testing.T) {
	code := `
#include <http_log.h>

void handle(server_rec *s) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "static startup message");
}
`
	flows := Analyze(code, "/app/mod_example.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected NO log flow for constant message -> ap_log_error")
	}
}

func TestC_NgxLogError_Safe(t *testing.T) {
	code := `
#include <ngx_core.h>

void on_request(ngx_log_t *log) {
    ngx_log_error(NGX_LOG_ERR, log, 0, "static error");
}
`
	flows := Analyze(code, "/app/ngx_module.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected NO log flow for constant message -> ngx_log_error")
	}
}

func TestC_Zlog_Safe(t *testing.T) {
	code := `
#include <zlog.h>

void log_startup(zlog_category_t *cat) {
    zlog_info(cat, "server started");
}
`
	flows := Analyze(code, "/app/server.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected NO log flow for constant message -> zlog_info")
	}
}
