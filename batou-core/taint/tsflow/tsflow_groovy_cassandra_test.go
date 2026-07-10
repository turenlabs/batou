package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// DataStax Cassandra / ScyllaDB CQL-injection sinks for Groovy.
// CqlSession (driver 4.x) and Session (legacy 3.x) accept raw CQL strings
// as their first argument, so tainted input flowing into arg 0 is CWE-943.
// Groovy GString interpolation collapses to a regular String, so the
// injection surface is identical to Java/Kotlin.
//
// Two flow shapes are exercised, mirroring the existing groovy_sql_test
// patterns:
//   1. Direct parameter -> sink (handler arg flowing straight into arg 0)
//   2. Second-order: ResultSet.getString -> string concat -> sink
//
// Pure parameter+string-concat is a known tsflow gap for Groovy and is
// not exercised here.

func TestGroovy_CassandraCqlSessionExecuteDirectParam(t *testing.T) {
	code := `
def handler(query) {
    cqlSession.execute(query)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkID(flows, "groovy.cassandra.cqlsession.execute") {
		t.Error("expected groovy.cassandra.cqlsession.execute finding for parameter -> cqlSession.execute")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

func TestGroovy_CassandraCqlSessionExecuteAsyncDirectParam(t *testing.T) {
	code := `
def handler(query) {
    cqlSession.executeAsync(query)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkID(flows, "groovy.cassandra.cqlsession.executeasync") {
		t.Error("expected groovy.cassandra.cqlsession.executeasync finding for parameter -> cqlSession.executeAsync")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

func TestGroovy_CassandraSimpleStatementNewInstanceDirectParam(t *testing.T) {
	code := `
def handler(query) {
    def stmt = SimpleStatement.newInstance(query)
    return stmt
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkID(flows, "groovy.cassandra.simplestatement.newinstance") {
		t.Error("expected groovy.cassandra.simplestatement.newinstance finding for parameter -> SimpleStatement.newInstance")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

func TestGroovy_CassandraSimpleStatementBuilderDirectParam(t *testing.T) {
	code := `
def handler(query) {
    def b = SimpleStatement.builder(query)
    return b.build()
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !findSinkID(flows, "groovy.cassandra.simplestatement.builder") {
		t.Error("expected groovy.cassandra.simplestatement.builder finding for parameter -> SimpleStatement.builder")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// Second-order CQL injection: tainted data flows from a ResultSet into a
// later cqlSession.execute call via string concatenation. Mirrors the
// dbext/sql_test second-order pattern.
func TestGroovy_CassandraSecondOrderInjection(t *testing.T) {
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT username FROM admins WHERE id = 1")
    def name = rs.getString("username")
    cqlSession.execute("SELECT * FROM activity WHERE user = '" + name + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected second-order CQL-injection flow for ResultSet.getString -> cqlSession.execute")
		for _, f := range flows {
			t.Logf("  flow: sink=%s cat=%s src=%s", f.Sink.ID, f.Sink.Category, f.Source.Category)
		}
	}
}

// Safe: the first arg is a hardcoded CQL string with ? placeholders;
// only the bound values come from user input. The sink's DangerousArgs
// is {0}, so this must not produce a finding for the new Cassandra sinks.
func TestGroovy_CassandraParameterizedQuerySafe(t *testing.T) {
	code := `
def handler(userId) {
    def stmt = SimpleStatement.newInstance("SELECT * FROM users WHERE id = ?", userId)
    cqlSession.execute(stmt)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		switch f.Sink.ID {
		case "groovy.cassandra.cqlsession.execute",
			"groovy.cassandra.simplestatement.newinstance":
			t.Errorf("unexpected finding on parameterized CQL query: sink=%s", f.Sink.ID)
		}
	}
}

func findSinkID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Sink.ID == id {
			return true
		}
	}
	return false
}
