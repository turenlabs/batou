package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C libbson document accessors as second-order taint sources.
//
// Values pulled out of a BSON document fetched from MongoDB (via the
// mongo-c-driver) are untrusted: a document written by an earlier request
// can carry attacker-controlled data that flows back into command, SQL, and
// other sinks (stored XSS / NoSQL re-injection / command injection).
//
// NOTE: tsflow's C walker does not propagate taint through C cast
// expressions like `(const char *)bson_iter_utf8(...)`, so the fixtures
// below omit casts (matching tsflow_c_parsed_data_sources_test.go).
// =========================================================================

func TestC_BsonIterUtf8_ToSystem(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void run(const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "cmd");
    const char *cmd = bson_iter_utf8(&iter, NULL);
    system(cmd);
}
`
	flows := Analyze(code, "/app/mongo_doc_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for bson_iter_utf8 -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterDupUtf8_ToPopen(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdio.h>

void run(const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "script");
    char *prog = bson_iter_dup_utf8(&iter, NULL);
    FILE *p = popen(prog, "r");
    (void)p;
}
`
	flows := Analyze(code, "/app/mongo_doc_popen.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for bson_iter_dup_utf8 -> popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterKey_ToMysqlQuery(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <mysql/mysql.h>

void run(MYSQL *conn, const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init(&iter, doc);
    bson_iter_next(&iter);
    const char *col = bson_iter_key(&iter);
    mysql_query(conn, col);
}
`
	flows := Analyze(code, "/app/mongo_key_sql.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for bson_iter_key -> mysql_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterInt32_ToSystem(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void run(const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "port");
    int port = bson_iter_int32(&iter);
    system(port);
}
`
	flows := Analyze(code, "/app/mongo_int32.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected flow for bson_iter_int32 -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterInt64_ToSystem(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void run(const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "size");
    long long n = bson_iter_int64(&iter);
    system(n);
}
`
	flows := Analyze(code, "/app/mongo_int64.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected flow for bson_iter_int64 -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterAsInt64_ToSystem(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void run(const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "n");
    long long n = bson_iter_as_int64(&iter);
    system(n);
}
`
	flows := Analyze(code, "/app/mongo_asint64.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected flow for bson_iter_as_int64 -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterCode_ToPopen(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdio.h>

void run(const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "hook");
    const char *js = bson_iter_code(&iter, NULL);
    FILE *p = popen(js, "r");
    (void)p;
}
`
	flows := Analyze(code, "/app/mongo_code.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected flow for bson_iter_code -> popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterCodeWScope_ToSystem(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void run(const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "hook");
    uint32_t clen = 0, slen = 0;
    const uint8_t *scope = NULL;
    const char *js = bson_iter_codewscope(&iter, &clen, &slen, &scope);
    system(js);
}
`
	flows := Analyze(code, "/app/mongo_codewscope.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected flow for bson_iter_codewscope -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterSymbol_ToMysqlQuery(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <mysql/mysql.h>

void run(MYSQL *conn, const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "sym");
    const char *s = bson_iter_symbol(&iter, NULL);
    mysql_query(conn, s);
}
`
	flows := Analyze(code, "/app/mongo_symbol.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for bson_iter_symbol -> mysql_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterRegex_ToSystem(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void run(const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "pat");
    const char *opts = NULL;
    const char *pattern = bson_iter_regex(&iter, &opts);
    system(pattern);
}
`
	flows := Analyze(code, "/app/mongo_regex.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected flow for bson_iter_regex -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonIterOid_ToSystem(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void run(const bson_t *doc) {
    bson_iter_t iter;
    bson_iter_init_find(&iter, doc, "_id");
    const bson_oid_t *oid = bson_iter_oid(&iter);
    system(oid);
}
`
	flows := Analyze(code, "/app/mongo_oid.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected flow for bson_iter_oid -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_BsonGetData_ToSystem(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void run(const bson_t *doc) {
    const uint8_t *buf = bson_get_data(doc);
    system(buf);
}
`
	flows := Analyze(code, "/app/mongo_getdata.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected flow for bson_get_data -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- End-to-end: MongoDB find -> cursor iterate -> bson_iter_utf8 -> sink ---

func TestC_Mongoc_CursorIterate_ToSystem(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void run(mongoc_collection_t *coll, bson_t *query) {
    mongoc_cursor_t *cur = mongoc_collection_find_with_opts(coll, query, NULL, NULL);
    const bson_t *doc;
    while (mongoc_cursor_next(cur, &doc)) {
        bson_iter_t iter;
        if (bson_iter_init_find(&iter, doc, "cmd")) {
            const char *cmd = bson_iter_utf8(&iter, NULL);
            system(cmd);
        }
    }
}
`
	flows := Analyze(code, "/app/mongo_cursor_iter.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for MongoDB cursor read -> bson_iter_utf8 -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative: literal / hardcoded arguments must not generate a flow ---

func TestC_BsonAccessors_LiteralCommand_NoFlow(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void run(void) {
    const char *cmd = "ls -la /tmp";
    system(cmd);
}
`
	flows := Analyze(code, "/app/safe_literal_bson.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO flow when command is a literal — verifies the libbson sources didn't over-broaden")
	}
}

// --- Catalog verification ---

func TestC_LibbsonSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangC)
	if cat == nil {
		t.Fatal("C catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sources() {
		found[s.ID] = true
	}
	want := []string{
		"c.libbson.iter_utf8", "c.libbson.iter_dup_utf8", "c.libbson.iter_key",
		"c.libbson.iter_int32", "c.libbson.iter_int64", "c.libbson.iter_as_int64",
		"c.libbson.iter_code", "c.libbson.iter_codewscope", "c.libbson.iter_symbol",
		"c.libbson.iter_regex", "c.libbson.iter_oid", "c.libbson.get_data",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SrcDatabase source: %s", id)
		}
	}
}
