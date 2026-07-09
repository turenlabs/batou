package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C libneo4j-client + seabolt Cypher injection tests (SnkSQLQuery / CWE-943)
// libneo4j-client: neo4j_run / neo4j_send take
//   (neo4j_connection_t*, const char *statement, neo4j_value_t params).
// seabolt: BoltConnection_set_run_cypher(connection, cypher, len, flags).
// The safe pattern is a literal Cypher template with $name placeholders plus
// a neo4j_map / BoltConnection_set_run_cypher_parameter for each value.
// =========================================================================

func TestC_Neo4j_Run_FromCGI(t *testing.T) {
	code := `
#include <neo4j-client.h>
#include <stdlib.h>

void run_user_query(neo4j_connection_t *connection) {
    const char *qs = getenv("QUERY_STRING");
    neo4j_result_stream_t *results = neo4j_run(connection, qs, neo4j_null);
    neo4j_close_results(results);
}
`
	flows := Analyze(code, "/app/neo4j_run.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for getenv -> neo4j_run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Neo4j_Send_FromCGI(t *testing.T) {
	code := `
#include <neo4j-client.h>
#include <stdlib.h>

void enqueue_user_query(neo4j_connection_t *connection) {
    const char *qs = getenv("QUERY_STRING");
    neo4j_result_stream_t *results = neo4j_send(connection, qs, neo4j_null);
    neo4j_close_results(results);
}
`
	flows := Analyze(code, "/app/neo4j_send.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for getenv -> neo4j_send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Seabolt_SetRunCypher_FromCGI(t *testing.T) {
	code := `
#include <bolt/bolt.h>
#include <stdlib.h>
#include <string.h>

void run_user_query(BoltConnection *connection) {
    const char *qs = getenv("QUERY_STRING");
    BoltConnection_set_run_cypher(connection, qs, strlen(qs), 0);
    BoltConnection_load_run_request(connection);
    BoltConnection_send(connection);
}
`
	flows := Analyze(code, "/app/seabolt_run.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for getenv -> BoltConnection_set_run_cypher")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe pattern: literal Cypher template with $name placeholders + parameter
// binding via neo4j_map. No tainted data reaches the statement string.
// =========================================================================

func TestC_Neo4j_LiteralWithMapParams_Safe(t *testing.T) {
	code := `
#include <neo4j-client.h>
#include <stdlib.h>

void run_safe_query(neo4j_connection_t *connection) {
    const char *qs = getenv("QUERY_STRING");
    neo4j_map_entry_t entries[1] = {
        neo4j_map_entry("name", neo4j_string(qs)),
    };
    neo4j_value_t params = neo4j_map(entries, 1);
    neo4j_result_stream_t *results = neo4j_run(connection,
        "MATCH (n:User {name: $name}) RETURN n", params);
    neo4j_close_results(results);
}
`
	flows := Analyze(code, "/app/neo4j_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO Cypher injection flow when statement is a literal + neo4j_map params; got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
