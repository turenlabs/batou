package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C hiredis Redis command-injection tests (SnkSQLQuery / CWE-943)
// =========================================================================

func TestC_Hiredis_RedisCommand_FromCGI(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <stdlib.h>

void run_user_cmd(redisContext *c) {
    const char *qs = getenv("QUERY_STRING");
    redisReply *r = redisCommand(c, qs);
    (void)r;
}
`
	flows := Analyze(code, "/app/redis_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Redis command injection flow for getenv -> redisCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Hiredis_RedisAppendCommand_FromCGI(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <stdlib.h>

void queue_user_cmd(redisContext *c) {
    const char *qs = getenv("QUERY_STRING");
    redisAppendCommand(c, qs);
}
`
	flows := Analyze(code, "/app/redis_pipeline.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Redis command injection flow for getenv -> redisAppendCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Hiredis_RedisvCommand_FromCGI(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <stdarg.h>
#include <stdlib.h>

void run_user_vcmd(redisContext *c, va_list ap) {
    const char *qs = getenv("QUERY_STRING");
    redisReply *r = redisvCommand(c, qs, ap);
    (void)r;
}
`
	flows := Analyze(code, "/app/redis_vcmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Redis command injection flow for getenv -> redisvCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Hiredis_RedisvAppendCommand_FromCGI(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <stdarg.h>
#include <stdlib.h>

void queue_user_vcmd(redisContext *c, va_list ap) {
    const char *qs = getenv("QUERY_STRING");
    redisvAppendCommand(c, qs, ap);
}
`
	flows := Analyze(code, "/app/redis_vpipeline.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Redis command injection flow for getenv -> redisvAppendCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Hiredis_RedisAsyncCommand_FromCGI(t *testing.T) {
	code := `
#include <hiredis/async.h>
#include <stdlib.h>

static void reply_cb(redisAsyncContext *ac, void *r, void *privdata) { (void)ac; (void)r; (void)privdata; }

void run_user_async(redisAsyncContext *ac) {
    const char *qs = getenv("QUERY_STRING");
    redisAsyncCommand(ac, reply_cb, NULL, qs);
}
`
	flows := Analyze(code, "/app/redis_async.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Redis command injection flow for getenv -> redisAsyncCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Hiredis_RedisvAsyncCommand_FromCGI(t *testing.T) {
	code := `
#include <hiredis/async.h>
#include <stdarg.h>
#include <stdlib.h>

static void reply_cb(redisAsyncContext *ac, void *r, void *privdata) { (void)ac; (void)r; (void)privdata; }

void run_user_vasync(redisAsyncContext *ac, va_list ap) {
    const char *qs = getenv("QUERY_STRING");
    redisvAsyncCommand(ac, reply_cb, NULL, qs, ap);
}
`
	flows := Analyze(code, "/app/redis_vasync.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Redis command injection flow for getenv -> redisvAsyncCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe pattern: literal format string with %s placeholder — no injection.
// =========================================================================

func TestC_Hiredis_RedisCommand_SafeWithFormatSpecifier(t *testing.T) {
	code := `
#include <hiredis/hiredis.h>
#include <stdlib.h>

void safe_get(redisContext *c) {
    const char *qs = getenv("QUERY_STRING");
    redisReply *r = redisCommand(c, "GET %s", qs);
    (void)r;
}
`
	flows := Analyze(code, "/app/redis_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect Redis injection flow when literal format string uses a placeholder")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
