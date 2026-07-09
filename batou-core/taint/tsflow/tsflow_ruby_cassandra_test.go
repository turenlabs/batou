package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — Apache Cassandra (DataStax cassandra-driver gem) CQL injection (CWE-943)
// =========================================================================
// Covers the cassandra-driver Ruby gem entries added to ruby_sinks.go:
//   - ruby.cassandra.session.execute
//   - ruby.cassandra.session.execute_async
//   - ruby.cassandra.session.prepare
//   - ruby.cassandra.session.prepare_async
//   - ruby.cassandra.statements.simple.new
// Each test wires a Rails-style params source through string interpolation
// or concatenation into the sink and asserts the SnkSQLQuery flow appears.

func TestRuby_Cassandra_Session_Execute_CQLInjection(t *testing.T) {
	code := `
require "cassandra"

def search(params)
  name = params[:name]
  cluster = Cassandra.cluster
  session = cluster.connect("ks")
  cql = "SELECT * FROM users WHERE name = '" + name + "'"
  session.execute(cql)
end
`
	flows := Analyze(code, "/app/controllers/cassandra_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for params -> Cassandra session.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Cassandra_Session_ExecuteAsync_CQLInjection(t *testing.T) {
	code := `
require "cassandra"

def search_async(params)
  name = params[:name]
  cluster = Cassandra.cluster
  session = cluster.connect("ks")
  session.execute_async("SELECT * FROM users WHERE name = '#{name}'")
end
`
	flows := Analyze(code, "/app/cassandra_async.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for params -> Cassandra session.execute_async")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Cassandra_Session_Prepare_CQLInjection(t *testing.T) {
	code := `
require "cassandra"

def prep(params)
  table = params[:table]
  cluster = Cassandra.cluster
  session = cluster.connect("ks")
  cql = "SELECT * FROM " + table + " WHERE id = ?"
  session.prepare(cql)
end
`
	flows := Analyze(code, "/app/cassandra_prep.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for params -> Cassandra session.prepare (interpolated body)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Cassandra_Session_PrepareAsync_CQLInjection(t *testing.T) {
	code := `
require "cassandra"

def prep_async(params)
  table = params[:table]
  cluster = Cassandra.cluster
  session = cluster.connect("ks")
  session.prepare_async("SELECT * FROM #{table} WHERE id = ?")
end
`
	flows := Analyze(code, "/app/cassandra_prep_async.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for params -> Cassandra session.prepare_async (interpolated body)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestRuby_Cassandra_StatementsSimple_New_CQLInjection(t *testing.T) {
	code := `
require "cassandra"

def build(params)
  name = params[:name]
  stmt = Cassandra::Statements::Simple.new("SELECT * FROM users WHERE name = '" + name + "'")
  session.execute(stmt)
end
`
	flows := Analyze(code, "/app/cassandra_simple.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for params -> Cassandra::Statements::Simple.new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sink=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative test: a constant CQL string passed with the :arguments option
// is the canonical safe pattern. We must not fire on this.
func TestRuby_Cassandra_Session_Execute_Parameterized_Safe(t *testing.T) {
	code := `
require "cassandra"

def search_safe(params)
  name = params[:name]
  cluster = Cassandra.cluster
  session = cluster.connect("ks")
  session.execute("SELECT * FROM users WHERE name = ?", arguments: [name])
end
`
	flows := Analyze(code, "/app/cassandra_safe.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.ID == "ruby.cassandra.session.execute" {
			t.Errorf("did not expect CQL injection flow when query is a constant and :arguments carries the value: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
