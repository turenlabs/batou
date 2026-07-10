package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Groovy Neo4j Cypher injection sinks (CWE-943).
// Neo4j executes Cypher via Session/Transaction/Neo4jClient.run|query;
// if the Cypher string is built from user input (Groovy GString
// "${name}" expands to a regular Java String at runtime), attackers
// can alter graph semantics. Safe code passes values as a Map argument
// alongside a literal $param placeholder in the Cypher.
//
// Two flow shapes are exercised, mirroring the existing
// tsflow_groovy_cassandra_test patterns:
//   1. Direct parameter -> sink (handler arg flowing straight into arg 0)
//   2. Second-order: ResultSet.getString -> string concat -> sink
//
// Pure parameter+string-concat is a known tsflow gap for Groovy and is
// not exercised here.

// --- Neo4j direct driver: Session.run ---

func TestGroovy_Neo4jSessionRunDirectParam(t *testing.T) {
	code := `
def handler(query) {
    session.run(query)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findGroovyNeo4jSinkID(flows, "groovy.neo4j.session.run") {
		t.Error("expected groovy.neo4j.session.run finding for parameter -> session.run")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Neo4j Transaction.run (explicit beginTransaction/commit) ---

func TestGroovy_Neo4jTxRunDirectParam(t *testing.T) {
	code := `
def handler(query) {
    def tx = session.beginTransaction()
    tx.run(query)
    tx.commit()
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findGroovyNeo4jSinkID(flows, "groovy.neo4j.tx.run") {
		t.Error("expected groovy.neo4j.tx.run finding for parameter -> tx.run")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Neo4j AsyncSession.runAsync ---

func TestGroovy_Neo4jAsyncSessionRunAsyncDirectParam(t *testing.T) {
	code := `
def handler(query) {
    asyncSession.runAsync(query)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findGroovyNeo4jSinkID(flows, "groovy.neo4j.asyncsession.runasync") {
		t.Error("expected groovy.neo4j.asyncsession.runasync finding for parameter -> asyncSession.runAsync")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Spring Data Neo4j: Neo4jClient.query ---

func TestGroovy_Neo4jClientQueryDirectParam(t *testing.T) {
	code := `
def handler(query) {
    neo4jClient.query(query)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findGroovyNeo4jSinkID(flows, "groovy.neo4j.sdn.neo4jclient.query") {
		t.Error("expected groovy.neo4j.sdn.neo4jclient.query finding for parameter -> neo4jClient.query")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Second-order Cypher injection: data from a ResultSet flows into
// session.run via string concatenation. Mirrors the dbext/sql_test
// second-order pattern. ---

func TestGroovy_Neo4jSecondOrderInjection(t *testing.T) {
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT username FROM admins WHERE id = 1")
    def name = rs.getString("username")
    session.run("MATCH (n:User {name: '" + name + "'}) RETURN n")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected second-order Cypher-injection flow for ResultSet.getString -> session.run")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// --- Safe: parameterized Cypher (literal first arg + params map). The
// sink's DangerousArgs is {0}, so passing user values via the Map
// second argument must not produce a finding. ---

func TestGroovy_Neo4jSessionRunParameterizedSafe(t *testing.T) {
	code := `
def handler(name) {
    session.run("MATCH (n:User {name: \$name}) RETURN n", [name: name])
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.ID == "groovy.neo4j.session.run" {
			t.Errorf("unexpected finding on parameterized Cypher query: sink=%s", f.Sink.ID)
		}
	}
}

func findGroovyNeo4jSinkID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Sink.ID == id {
			return true
		}
	}
	return false
}
