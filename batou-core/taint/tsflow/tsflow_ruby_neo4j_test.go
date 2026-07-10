package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — Neo4j Cypher injection sinks (CWE-943)
// =========================================================================
// These tests cover the three Neo4j entry points added to ruby_sinks.go:
//   - ruby.neo4j.active_base.run_query  (activegraph / older neo4j gem)
//   - ruby.active_graph.base.query      (activegraph newer API)
//   - ruby.neo4j.driver.execute_query   (neo4j-ruby-driver v5+ unified API)
// Each test wires a Rails/Sinatra-style params source through string
// interpolation into the sink and asserts the SnkSQLQuery flow appears.

func TestRuby_Neo4j_ActiveBase_RunQuery_CypherInjection(t *testing.T) {
	code := `
require "neo4j/active_base"

def search(params)
  name = params[:name]
  cypher = "MATCH (u:User {name: '" + name + "'}) RETURN u"
  Neo4j::ActiveBase.run_query(cypher)
end
`
	flows := Analyze(code, "/app/controllers/search_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for params -> Neo4j::ActiveBase.run_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Neo4j_ActiveGraph_Base_Query_CypherInjection(t *testing.T) {
	code := `
require "active_graph"

def by_label(params)
  label = params[:label]
  cypher = "MATCH (n:" + label + ") RETURN n"
  ActiveGraph::Base.query(cypher)
end
`
	flows := Analyze(code, "/app/controllers/nodes_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for params -> ActiveGraph::Base.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Neo4j_Driver_ExecuteQuery_CypherInjection(t *testing.T) {
	code := `
require "neo4j/driver"

def lookup(params)
  email = params[:email]
  driver = Neo4j::Driver::GraphDatabase.driver("bolt://localhost:7687", auth)
  cypher = "MATCH (u:User {email: '" + email + "'}) RETURN u"
  driver.execute_query(cypher)
end
`
	flows := Analyze(code, "/app/lookup.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Cypher injection flow for params -> Neo4j driver.execute_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative test: a constant Cypher string passed with a params hash is safe.
// Ensures we don't fire when only the params hash carries the tainted value.
func TestRuby_Neo4j_Driver_ExecuteQuery_Parameterized_Safe(t *testing.T) {
	code := `
require "neo4j/driver"

def lookup(params)
  email = params[:email]
  driver = Neo4j::Driver::GraphDatabase.driver("bolt://localhost:7687", auth)
  driver.execute_query("MATCH (u:User {email: $email}) RETURN u", email: email)
end
`
	flows := Analyze(code, "/app/lookup_safe.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.ID == "ruby.neo4j.driver.execute_query" {
			t.Errorf("did not expect Cypher injection flow when query is a constant and params hash carries the value: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
