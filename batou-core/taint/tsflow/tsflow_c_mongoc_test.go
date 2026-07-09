package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C libmongoc NoSQL injection tests (SnkSQLQuery / CWE-943)
// =========================================================================

func TestC_Mongoc_CollectionCommandSimple_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void run_user_cmd(mongoc_collection_t *coll) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *cmd = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    mongoc_collection_command_simple(coll, cmd, NULL, NULL, NULL);
}
`
	flows := Analyze(code, "/app/mongo_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_collection_command_simple")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_DatabaseCommandSimple_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void run_db_cmd(mongoc_database_t *db) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *cmd = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    mongoc_database_command_simple(db, cmd, NULL, NULL, NULL);
}
`
	flows := Analyze(code, "/app/mongo_db_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_database_command_simple")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_ClientCommandSimple_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void run_client_cmd(mongoc_client_t *client) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *cmd = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    mongoc_client_command_simple(client, "appdb", cmd, NULL, NULL, NULL);
}
`
	flows := Analyze(code, "/app/mongo_client_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_client_command_simple")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_CollectionFindWithOpts_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void find_user(mongoc_collection_t *coll) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *filter = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    mongoc_cursor_t *cur = mongoc_collection_find_with_opts(coll, filter, NULL, NULL);
    (void)cur;
}
`
	flows := Analyze(code, "/app/mongo_find.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_collection_find_with_opts")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_CollectionAggregate_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void run_pipeline(mongoc_collection_t *coll) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *pipeline = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    mongoc_cursor_t *cur = mongoc_collection_aggregate(coll, MONGOC_QUERY_NONE, pipeline, NULL, NULL);
    (void)cur;
}
`
	flows := Analyze(code, "/app/mongo_agg.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_collection_aggregate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_DatabaseAggregate_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void run_db_pipeline(mongoc_database_t *db) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *pipeline = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    mongoc_cursor_t *cur = mongoc_database_aggregate(db, pipeline, NULL, NULL);
    (void)cur;
}
`
	flows := Analyze(code, "/app/mongo_db_agg.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_database_aggregate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_CollectionUpdateOne_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void update_user(mongoc_collection_t *coll) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *update = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    bson_t selector = BSON_INITIALIZER;
    mongoc_collection_update_one(coll, &selector, update, NULL, NULL, NULL);
}
`
	flows := Analyze(code, "/app/mongo_update_one.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_collection_update_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_CollectionUpdateMany_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void update_users(mongoc_collection_t *coll) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *selector = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    bson_t update = BSON_INITIALIZER;
    mongoc_collection_update_many(coll, selector, &update, NULL, NULL, NULL);
}
`
	flows := Analyze(code, "/app/mongo_update_many.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_collection_update_many")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_CollectionReplaceOne_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void replace_user(mongoc_collection_t *coll) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *replacement = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    bson_t selector = BSON_INITIALIZER;
    mongoc_collection_replace_one(coll, &selector, replacement, NULL, NULL, NULL);
}
`
	flows := Analyze(code, "/app/mongo_replace.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_collection_replace_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_CollectionDeleteOne_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void remove_record(mongoc_collection_t *coll) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *selector = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    mongoc_collection_delete_one(coll, selector, NULL, NULL, NULL);
}
`
	flows := Analyze(code, "/app/mongo_delete_one.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_collection_delete_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mongoc_CollectionDeleteMany_FromCGI(t *testing.T) {
	code := `
#include <mongoc/mongoc.h>
#include <stdlib.h>

void remove_records(mongoc_collection_t *coll) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *selector = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    mongoc_collection_delete_many(coll, selector, NULL, NULL, NULL);
}
`
	flows := Analyze(code, "/app/mongo_delete_many.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for getenv -> mongoc_collection_delete_many")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C libbson JSON-to-BSON deserialization test (SnkDeserialize / CWE-502)
// =========================================================================

func TestC_Bson_NewFromJson_FromCGI(t *testing.T) {
	code := `
#include <bson/bson.h>
#include <stdlib.h>

void parse_user_json(void) {
    const char *qs = getenv("QUERY_STRING");
    bson_t *doc = bson_new_from_json((const uint8_t *)qs, -1, NULL);
    (void)doc;
}
`
	flows := Analyze(code, "/app/bson_parse.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow for getenv -> bson_new_from_json")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
