package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for the Kotlin Spring JdbcTemplate second-order DB-read sources added to
// kotlin_sources.go: query / queryForObject / queryForList / queryForMap /
// queryForRowSet / queryForStream. These read rows back from the database; an
// attacker who can influence stored data (a first-order write elsewhere) can
// re-introduce a payload that flows into a downstream sink — the classic
// second-order injection shape. Kotlin already modelled the query-STRING side of
// these calls as SnkSQLQuery sinks (kotlin_sinks.go) but not the returned data;
// this closes that sink/source asymmetry, matching Java and Groovy.
//
// Each positive test reads from a CONSTANT query (so the call does NOT fire as a
// sink) and concatenates the tainted result into an existing Kotlin sink
// (Statement.executeUpdate / Runtime.exec). The negative test confirms a
// .toInt() coercion in the path neutralises SnkSQLQuery/SnkCommand.
//
// The matcher relies on ObjectType+MethodName (Pattern is regex-fallback only):
// ObjectType "JdbcTemplate" matches receiver `jdbcTemplate` via the
// prefix-abbreviation heuristic in matcher.go.

func TestKotlin_JdbcTemplateQueryForObject_ToSQLInjection(t *testing.T) {
	code := `
fun reportAuthor() {
    val name = jdbcTemplate.queryForObject("SELECT name FROM users WHERE id = 1", String::class.java)
    val statement = conn.createStatement()
    statement.executeUpdate("DELETE FROM logs WHERE author = '" + name + "'")
}
`
	flows := Analyze(code, "/app/handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JdbcTemplate.queryForObject -> executeUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_JdbcTemplateQueryForList_ToCommand(t *testing.T) {
	code := `
fun runJobs() {
    val items = jdbcTemplate.queryForList("SELECT cmd FROM jobs")
    Runtime.getRuntime().exec("sh -c " + items)
}
`
	flows := Analyze(code, "/app/handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for JdbcTemplate.queryForList -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_JdbcTemplateQueryForMap_ToSQLInjection(t *testing.T) {
	code := `
fun loadRow() {
    val row = jdbcTemplate.queryForMap("SELECT * FROM users WHERE id = 1")
    val statement = conn.createStatement()
    statement.executeUpdate("UPDATE audit SET who = '" + row + "'")
}
`
	flows := Analyze(code, "/app/handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JdbcTemplate.queryForMap -> executeUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_JdbcTemplateQueryForRowSet_ToCommand(t *testing.T) {
	code := `
fun exportRows() {
    val rs = jdbcTemplate.queryForRowSet("SELECT path FROM files")
    Runtime.getRuntime().exec("cat " + rs)
}
`
	flows := Analyze(code, "/app/handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for JdbcTemplate.queryForRowSet -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_JdbcTemplateQueryForStream_ToSQLInjection(t *testing.T) {
	code := `
fun streamRows() {
    val stream = jdbcTemplate.queryForStream("SELECT tag FROM rows", rowMapper)
    val statement = conn.createStatement()
    statement.executeUpdate("INSERT INTO copy VALUES ('" + stream + "')")
}
`
	flows := Analyze(code, "/app/handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JdbcTemplate.queryForStream -> executeUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_JdbcTemplateQuery_ToCommand(t *testing.T) {
	code := `
fun mapResults() {
    val results = jdbcTemplate.query("SELECT host FROM nodes", rowMapper)
    Runtime.getRuntime().exec("ping " + results)
}
`
	flows := Analyze(code, "/app/handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for JdbcTemplate.query -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a .toInt() coercion on the DB read neutralises the taint
// before it reaches the command sink, so no flow should be reported. This also
// confirms the positive tests are not firing on something other than the new
// source (e.g. an unrelated auto-tainted parameter).
func TestKotlin_JdbcTemplateQueryForObject_Coerced_Safe(t *testing.T) {
	code := `
fun safeCount() {
    val raw = jdbcTemplate.queryForObject("SELECT count FROM t", String::class.java)
    val safe = raw.toInt()
    Runtime.getRuntime().exec("echo " + safe)
}
`
	flows := Analyze(code, "/app/handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did NOT expect a command flow — .toInt() should neutralise the DB read")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
