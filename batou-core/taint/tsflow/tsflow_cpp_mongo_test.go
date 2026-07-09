package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C++ mongocxx NoSQL injection tests (CWE-943)
// =========================================================================

func TestCPP_Mongocxx_Find_NoSQLInjection(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <mongocxx/collection.hpp>
#include <bsoncxx/json.hpp>

void handler(const char* argv[]) {
    std::string raw = argv[1];
    mongocxx::collection coll;
    auto filter = bsoncxx::from_json(raw);
    auto cursor = coll.find(filter);
}
`
	flows := Analyze(code, "/app/mongo_find.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for argv -> mongocxx::collection.find")
	}
}

//
// mongocxx is the official MongoDB C++ driver. Collection operations accept
// a BSON filter — if that filter is built from user-controlled JSON via
// bsoncxx::from_json(), an attacker can inject operators like $where, $ne,
// $gt to bypass authentication or exfiltrate data.
// =========================================================================

func TestCPP_MongocxxFindOne_Tainted(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/json.hpp>
#include <cstdlib>

void lookup(mongocxx::collection coll) {
    const char *user = std::getenv("USER_FILTER");
    auto filter = bsoncxx::from_json(user);
    auto result = coll.find_one(filter.view());
}
`
	flows := Analyze(code, "/app/mongo_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for getenv -> bsoncxx::from_json -> find_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MongocxxFindOneAndUpdate_Tainted(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/json.hpp>
#include <cstdlib>

void atomic_update(mongocxx::collection coll) {
    const char *user = std::getenv("FILTER_JSON");
    auto filter = bsoncxx::from_json(user);
    coll.find_one_and_update(filter.view(), update);
}
`
	flows := Analyze(code, "/app/mongo_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for find_one_and_update")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MongocxxUpdateMany_Tainted(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/json.hpp>
#include <cstdlib>

void mass_update(mongocxx::collection coll) {
    const char *user = std::getenv("BULK_FILTER");
    auto filter = bsoncxx::from_json(user);
    coll.update_many(filter.view(), update_doc);
}
`
	flows := Analyze(code, "/app/mongo_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for update_many")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MongocxxDeleteOne_Tainted(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/json.hpp>
#include <cstdlib>

void remove_doc(mongocxx::collection coll) {
    const char *user = std::getenv("DELETE_FILTER");
    auto filter = bsoncxx::from_json(user);
    coll.delete_one(filter.view());
}
`
	flows := Analyze(code, "/app/mongo_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for delete_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MongocxxReplaceOne_Tainted(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/json.hpp>
#include <cstdlib>

void replace(mongocxx::collection coll) {
    const char *user = std::getenv("USER_FILTER");
    auto filter = bsoncxx::from_json(user);
    coll.replace_one(filter.view(), replacement);
}
`
	flows := Analyze(code, "/app/mongo_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for replace_one")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_BsoncxxFromJson_Tainted(t *testing.T) {
	code := `
#include <bsoncxx/json.hpp>
#include <cstdlib>

void parse_user_filter() {
    const char *raw = std::getenv("RAW_FILTER");
    auto filter = bsoncxx::from_json(raw);
}
`
	flows := Analyze(code, "/app/mongo_handler.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for bsoncxx::from_json(user_input)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mongocxx_FindOneAndUpdate_NoSQLInjection(t *testing.T) {
	code := `
#include <mongocxx/collection.hpp>
#include <bsoncxx/json.hpp>

void handler(const char* argv[]) {
    std::string raw = argv[1];
    mongocxx::collection coll;
    auto filter = bsoncxx::from_json(raw);
    auto result = coll.find_one_and_update(filter, bsoncxx::from_json("{}"));
}
`
	flows := Analyze(code, "/app/mongo_fou.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for argv -> find_one_and_update")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mongocxx_DeleteMany_NoSQLInjection(t *testing.T) {
	code := `
#include <mongocxx/collection.hpp>
#include <bsoncxx/json.hpp>

void handler(const char* argv[]) {
    std::string raw = argv[1];
    mongocxx::collection coll;
    auto filter = bsoncxx::from_json(raw);
    auto result = coll.delete_many(filter);
}
`
	flows := Analyze(code, "/app/mongo_delete.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for argv -> delete_many")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mongocxx_Aggregate_NoSQLInjection(t *testing.T) {
	code := `
#include <mongocxx/collection.hpp>
#include <bsoncxx/json.hpp>

void handler(const char* argv[]) {
    std::string raw = argv[1];
    mongocxx::collection coll;
    auto pipeline = bsoncxx::from_json(raw);
    auto cursor = coll.aggregate(pipeline);
}
`
	flows := Analyze(code, "/app/mongo_agg.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for argv -> aggregate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mongocxx_RunCommand_NoSQLInjection(t *testing.T) {
	code := `
#include <mongocxx/database.hpp>
#include <bsoncxx/json.hpp>

void handler(const char* argv[]) {
    std::string raw = argv[1];
    mongocxx::database db;
    auto cmd = bsoncxx::from_json(raw);
    auto result = db.run_command(cmd);
}
`
	flows := Analyze(code, "/app/mongo_runcmd.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NoSQL injection flow for argv -> database.run_command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Mongocxx_Safe_HardcodedFilter(t *testing.T) {
	code := `
#include <mongocxx/collection.hpp>
#include <bsoncxx/builder/stream/document.hpp>

void healthcheck() {
    mongocxx::collection coll;
    bsoncxx::builder::stream::document filter_builder;
    filter_builder << "status" << "active";
    auto cursor = coll.find(filter_builder.view());
}
`
	flows := Analyze(code, "/app/mongo_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected NoSQL flow on hardcoded filter: %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MongocxxFindOne_Safe(t *testing.T) {
	code := `
#include <mongocxx/client.hpp>
#include <bsoncxx/builder/stream/document.hpp>

void lookup(mongocxx::collection coll) {
    bsoncxx::builder::stream::document filter{};
    filter << "status" << "active";
    auto result = coll.find_one(filter.view());
}
`
	flows := Analyze(code, "/app/mongo_handler.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO NoSQL flow when filter is built from static strings")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
