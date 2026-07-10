package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Groovy DataStax Cassandra Row read sources — second-order taint tests.
//
// Groovy's catalog already had Cassandra SINKS
// (groovy.cassandra.cqlsession.execute/.executeasync,
// groovy.cassandra.simplestatement.newinstance/.builder) but no Cassandra
// SOURCES, so attacker bytes written to a table on one request and read back
// via `row.getString(...)` on a later request did not propagate taint. These
// fixtures read a column value out of a Cassandra Row and flow it, unsanitized,
// into a SQL (sql.execute) or command (Runtime.exec) sink.
//
// All fixtures use the canonical receiver name `row` (from `def row = rs.one()`
// or `for (row in rs)`), which anchors to ObjectType "Row" via the matcher's
// prefix-abbreviation heuristic. Because Groovy is dynamically typed, the
// collection getters (getList/getSet/getMap) propagate taint through a direct
// string concatenation (implicit toString() goes through the `+` operator taint
// path) — the same convention the Groovy JDBC/MyBatis read-source tests use.
// =========================================================================

func TestGroovy_CassandraRowSources_Registered(t *testing.T) {
	want := []string{
		"groovy.cassandra.row.getstring",
		"groovy.cassandra.row.getobject",
		"groovy.cassandra.row.getlist",
		"groovy.cassandra.row.getset",
		"groovy.cassandra.row.getmap",
	}
	sources := taint.SourcesForLanguage(rules.LangGroovy)
	for _, id := range want {
		found := false
		for _, s := range sources {
			if s.ID == id {
				if s.Category != taint.SrcDatabase {
					t.Errorf("source %s: expected category %v, got %v", id, taint.SrcDatabase, s.Category)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("source %s not found in Groovy catalog", id)
		}
	}
}

// ---------- Row.getString(name) → SQL injection (CWE-89) ----------

func TestGroovy_CassandraRow_GetString_ToSQLInjection(t *testing.T) {
	code := `
def render() {
    def rs = session.execute("SELECT display_name FROM users LIMIT 1")
    def row = rs.one()
    def displayName = row.getString("display_name")
    sql.execute("SELECT * FROM events WHERE name = '" + displayName + "'")
}
`
	flows := Analyze(code, "/app/ProfileRepo.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Row.getString -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------- Row.getObject(name) → command injection (CWE-78) ----------

func TestGroovy_CassandraRow_GetObject_ToCommand(t *testing.T) {
	code := `
def runJob() {
    def row = session.execute("SELECT cmd FROM jobs LIMIT 1").one()
    def cmd = row.getObject("cmd")
    Runtime.getRuntime().exec("sh -c " + cmd)
}
`
	flows := Analyze(code, "/app/JobRunner.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Row.getObject -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------- Row.getList(name, clazz) → SQL injection (CWE-89) ----------

func TestGroovy_CassandraRow_GetList_ToSQLInjection(t *testing.T) {
	code := `
def listTags() {
    def row = session.execute("SELECT tags FROM posts LIMIT 1").one()
    def tags = row.getList("tags", String.class)
    sql.execute("SELECT * FROM items WHERE tag = '" + tags + "'")
}
`
	flows := Analyze(code, "/app/TagRepo.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Row.getList -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------- Row.getSet(name, clazz) → SQL injection (CWE-89) ----------

func TestGroovy_CassandraRow_GetSet_ToSQLInjection(t *testing.T) {
	code := `
def syncRoles() {
    def row = session.execute("SELECT roles FROM accounts LIMIT 1").one()
    def roles = row.getSet("roles", String.class)
    sql.execute("UPDATE perms SET payload = '" + roles + "'")
}
`
	flows := Analyze(code, "/app/RoleRepo.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Row.getSet -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------- Row.getMap(name, k, v) → SQL injection (CWE-89) ----------

func TestGroovy_CassandraRow_GetMap_ToSQLInjection(t *testing.T) {
	code := `
def applyConfig() {
    def row = session.execute("SELECT settings FROM config LIMIT 1").one()
    def settings = row.getMap("settings", String.class, String.class)
    sql.execute("INSERT INTO cfg (payload) VALUES ('" + settings + "')")
}
`
	flows := Analyze(code, "/app/ConfigRepo.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Row.getMap -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test — a tainted Row read coerced through Integer.parseInt() is no
// longer SQL-injectable, so no SnkSQLQuery flow should be reported.
func TestGroovy_CassandraRow_Sanitized_NoFlow(t *testing.T) {
	code := `
def lookupEvents() {
    def row = session.execute("SELECT user_id FROM users LIMIT 1").one()
    def raw = row.getString("user_id")
    def id = Integer.parseInt(raw)
    sql.execute("SELECT * FROM events WHERE user_id = " + id)
}
`
	flows := Analyze(code, "/app/EventRepo.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when Row result is sanitized via parseInt")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
