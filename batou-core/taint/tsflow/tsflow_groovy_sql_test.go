package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for groovy.sql.Sql SQL injection sinks beyond the core execute/rows/
// firstRow/executeUpdate set: eachRow, executeInsert, callWithRows,
// callWithAllRows. All four are documented on groovy.sql.Sql and accept a raw
// SQL string as their first argument, so tainted input in arg 0 is CWE-89.
//
// The test style matches tsflow_groovy_dbext_test.go: the taint source is a
// database ResultSet (rs.getString/getObject), which then flows through
// string concatenation into the new sinks. This mirrors the second-order
// SQL-injection pattern — storing user input in one row then interpolating
// it into another query.

func TestGroovy_SqlEachRowInjection(t *testing.T) {
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT author FROM posts WHERE id = 1")
    def author = rs.getString("author")
    sql.eachRow("SELECT * FROM logs WHERE user = '" + author + "'") { row ->
        println row.msg
    }
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ResultSet.getString -> sql.eachRow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SqlExecuteInsertInjection(t *testing.T) {
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT name FROM import_queue WHERE id = 1")
    def name = rs.getString("name")
    def keys = sql.executeInsert("INSERT INTO users(name) VALUES('" + name + "')")
    return keys
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ResultSet.getString -> sql.executeInsert")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SqlCallWithRowsInjection(t *testing.T) {
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT dept FROM queue WHERE id = 1")
    def dept = rs.getString("dept")
    sql.callWithRows("{call find_employees('" + dept + "')}") { rows ->
        rows.each { println it }
    }
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ResultSet.getString -> sql.callWithRows")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SqlCallWithAllRowsInjection(t *testing.T) {
	code := `
def handler() {
    def rs = stmt.executeQuery("SELECT region FROM queue WHERE id = 1")
    def region = rs.getString("region")
    sql.callWithAllRows("{call reports_by_region('" + region + "')}") { rsets ->
        rsets.each { rs2 -> println rs2 }
    }
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for ResultSet.getString -> sql.callWithAllRows")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Direct-parameter form: confirms the sink fires when tainted input reaches
// the first argument without string concatenation.
func TestGroovy_SqlEachRowDirectParam(t *testing.T) {
	code := `
def handler(query) {
    sql.eachRow(query) { row -> println row }
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for parameter -> sql.eachRow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
