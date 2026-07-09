package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — second-order NoSQL read sources for the graph / wide-column drivers
// whose write-side injection sinks already exist but whose read side did not
// carry taint: Cassandra::Session#execute, Neo4j::Driver#execute_query, and
// Neo4j::ActiveBase.run_query. Data stored on an earlier request and read back
// later flows into a downstream sink (second-order CQL / Cypher injection).
//
// Mirrors the cross-language second-order wave already landed for these same
// stores: csharp DataStax Cassandra (#1119), go gocql (#1122), and the ruby
// raw-SQL / Mongo read sources in tsflow_ruby_db_read_sources_test.go.
//
// Test note (same idiom as tsflow_ruby_db_read_sources_test.go): fixtures take
// NO params (so seedParams() can't auto-taint anything — the DB read is the
// only taint origin), assign the source call to its own variable, then extract
// a column with `.to_a[0]["col"]`. The query argument is a constant so the
// dual-role sink (these methods are also injection sinks) cannot fire on it —
// the flow under test originates purely from the returned rows.
// =========================================================================

func TestRuby_GraphRead_CassandraExecute_CommandInjection(t *testing.T) {
	code := `
require "cassandra"

def report
  cluster = Cassandra.cluster
  session = cluster.connect("ks")
  rows = session.execute("SELECT note FROM audit_log")
  note = rows.to_a[0]["note"]
  system("logger " + note)
end
`
	flows := Analyze(code, "/app/jobs/cassandra_report_job.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Cassandra::Session#execute result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_GraphRead_Neo4jExecuteQuery_CommandInjection(t *testing.T) {
	code := `
require "neo4j/driver"

def show_name
  driver = Neo4j::Driver::GraphDatabase.driver("bolt://localhost")
  result = driver.execute_query("MATCH (u:User) RETURN u.name AS name LIMIT 1")
  name = result.to_a[0]["name"]
  system("echo " + name)
end
`
	flows := Analyze(code, "/app/services/neo4j_name_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Neo4j::Driver#execute_query result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_GraphRead_Neo4jRunQuery_CommandInjection(t *testing.T) {
	code := `
require "neo4j/core"

def list_labels
  result = Neo4j::ActiveBase.run_query("MATCH (t:Tag) RETURN t.label AS label LIMIT 1")
  label = result.to_a[0]["label"]
  system("echo " + label)
end
`
	flows := Analyze(code, "/app/services/neo4j_label_service.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Neo4j::ActiveBase.run_query result -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative control: a Cassandra read whose result flows only into a constant
// (no tainted data reaches a sink) must NOT produce a command-injection flow.
func TestRuby_GraphRead_Cassandra_NoFlow_Constant(t *testing.T) {
	code := `
require "cassandra"

def healthcheck
  cluster = Cassandra.cluster
  session = cluster.connect("ks")
  rows = session.execute("SELECT 1")
  system("echo ok")
end
`
	flows := Analyze(code, "/app/jobs/cassandra_health_job.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command injection flow when the Cassandra result is unused")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
