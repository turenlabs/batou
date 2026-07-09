package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ libneo4j-client + seabolt Cypher injection tests (SnkSQLQuery / CWE-943)
// libneo4j-client and seabolt are pure-C drivers commonly bundled into C++
// applications. The same neo4j_run / neo4j_send / BoltConnection_set_run_cypher
// entry points are dangerous regardless of the calling language. The safe
// pattern is a literal Cypher template with $name placeholders + parameter
// binding via neo4j_map / BoltConnection_set_run_cypher_parameter.
// =========================================================================

func TestCPP_Neo4j_Run_Injection(t *testing.T) {
	code := `
#include <neo4j-client.h>
#include <string>

void run_user_query(neo4j_connection_t *connection, const char* argv[]) {
    std::string user_id = argv[1];
    std::string q = "MATCH (n:User {id: '" + user_id + "'}) RETURN n";
    neo4j_result_stream_t *results = neo4j_run(connection, q.c_str(), neo4j_null);
    neo4j_close_results(results);
}
`
	flows := Analyze(code, "/app/neo4j_run.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for argv -> neo4j_run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Neo4j_Send_Injection(t *testing.T) {
	code := `
#include <neo4j-client.h>
#include <string>

void enqueue_user_query(neo4j_connection_t *connection, const char* argv[]) {
    std::string label = argv[1];
    std::string q = "MATCH (n:" + label + ") RETURN n LIMIT 100";
    neo4j_result_stream_t *results = neo4j_send(connection, q.c_str(), neo4j_null);
    neo4j_close_results(results);
}
`
	flows := Analyze(code, "/app/neo4j_send.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for argv -> neo4j_send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Seabolt_SetRunCypher_Injection(t *testing.T) {
	code := `
#include <bolt/bolt.h>
#include <string>
#include <cstring>

void run_user_query(BoltConnection *connection, const char* argv[]) {
    std::string name = argv[1];
    std::string cypher = "MATCH (p:Person {name: '" + name + "'}) RETURN p";
    BoltConnection_set_run_cypher(connection, cypher.c_str(), cypher.size(), 0);
    BoltConnection_load_run_request(connection);
    BoltConnection_send(connection);
}
`
	flows := Analyze(code, "/app/seabolt_run.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for argv -> BoltConnection_set_run_cypher")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe pattern: literal Cypher template with $name placeholders + parameter
// binding via neo4j_map. No tainted data reaches the statement string.
// =========================================================================

func TestCPP_Neo4j_LiteralWithMapParams_Safe(t *testing.T) {
	code := `
#include <neo4j-client.h>
#include <string>

void run_safe_query(neo4j_connection_t *connection, const char* argv[]) {
    std::string user_id = argv[1];
    neo4j_map_entry_t entries[1] = {
        neo4j_map_entry("id", neo4j_string(user_id.c_str())),
    };
    neo4j_value_t params = neo4j_map(entries, 1);
    neo4j_result_stream_t *results = neo4j_run(connection,
        "MATCH (n:User {id: $id}) RETURN n", params);
    neo4j_close_results(results);
}
`
	flows := Analyze(code, "/app/neo4j_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO Cypher injection flow when statement is a literal + neo4j_map params; got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
