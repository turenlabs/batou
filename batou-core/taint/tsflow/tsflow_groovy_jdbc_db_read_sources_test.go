package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for the Groovy second-order DB-read sources added to groovy_sources.go:
// Spring JdbcTemplate query results (queryForObject/queryForList/queryForMap/
// queryForRowSet/queryForStream/query), MyBatis SqlSession select results
// (selectOne/selectList/selectMap), and JPA Query result completions
// (getSingleResult/getResultStream).
//
// These methods read rows from the database; an attacker who can influence
// stored data (first-order write elsewhere) can re-introduce a payload that
// flows into a downstream sink — the classic second-order injection shape.
// Each positive test takes the tainted DB read through a string concatenation
// into an existing Groovy sink (sql.execute / Runtime.exec). The negative test
// confirms an Integer.parseInt() in the path neutralises SnkSQLQuery.
//
// The matcher relies on ObjectType+MethodName (Pattern is regex-fallback only):
//   - "JdbcTemplate" matches receiver `jdbcTemplate` (and `jdbc`, `j` via the
//     prefix-abbreviation heuristic in matcher.go)
//   - "SqlSession" matches `sqlSession` and (via the "session" special case)
//     `session`/`sess`/`s`
//   - "Query" matches `query` and `q`

func TestGroovy_JdbcTemplateQueryForObject_ToSQLInjection(t *testing.T) {
	code := `
def reportAuthor() {
    def name = jdbcTemplate.queryForObject("SELECT name FROM users WHERE id = 1", String.class)
    sql.execute("SELECT * FROM logs WHERE author = '" + name + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JdbcTemplate.queryForObject -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JdbcTemplateQueryForList_ToCommand(t *testing.T) {
	code := `
def runJobs() {
    def items = jdbcTemplate.queryForList("SELECT cmd FROM jobs")
    Runtime.getRuntime().exec("sh -c " + items)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for JdbcTemplate.queryForList -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JdbcTemplateQueryForMap_ToSQLInjection(t *testing.T) {
	code := `
def applyConfig() {
    def row = jdbcTemplate.queryForMap("SELECT key, val FROM config WHERE id = 1")
    sql.execute("UPDATE settings SET payload = '" + row + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JdbcTemplate.queryForMap -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JdbcTemplateQueryForRowSet_ToSQLInjection(t *testing.T) {
	code := `
def auditAccounts() {
    def rs = jdbcTemplate.queryForRowSet("SELECT acct FROM accounts")
    sql.execute("SELECT * FROM audit WHERE acct = '" + rs + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JdbcTemplate.queryForRowSet -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JdbcTemplateQueryForStream_ToSQLInjection(t *testing.T) {
	code := `
def collectEvents() {
    def stream = jdbcTemplate.queryForStream("SELECT detail FROM events", rowMapper)
    sql.execute("INSERT INTO report (detail) VALUES ('" + stream + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JdbcTemplate.queryForStream -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JdbcTemplateQuery_ToSQLInjection(t *testing.T) {
	code := `
def listItems() {
    def rows = jdbcTemplate.query("SELECT label FROM tags", rowMapper)
    sql.execute("SELECT * FROM items WHERE tag = '" + rows + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JdbcTemplate.query -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MyBatisSelectOne_ToSQLInjection(t *testing.T) {
	code := `
def cleanupSessions() {
    def user = sqlSession.selectOne("UserMapper.findById", 1)
    sql.execute("DELETE FROM sessions WHERE owner = '" + user + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for MyBatis SqlSession.selectOne -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MyBatisSelectList_ToCommand(t *testing.T) {
	code := `
def runQueued() {
    def cmds = session.selectList("JobMapper.all")
    Runtime.getRuntime().exec("sh -c " + cmds)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for MyBatis SqlSession.selectList -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MyBatisSelectMap_ToSQLInjection(t *testing.T) {
	code := `
def syncConfig() {
    def m = sqlSession.selectMap("ConfigMapper.all", "key")
    sql.execute("UPDATE cfg SET payload = '" + m + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for MyBatis SqlSession.selectMap -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JpaQueryGetSingleResult_ToSQLInjection(t *testing.T) {
	code := `
def reportTotal() {
    def total = query.getSingleResult()
    sql.execute("SELECT * FROM totals WHERE label = '" + total + "'")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JPA Query.getSingleResult -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JpaQueryGetResultStream_ToSQLInjection(t *testing.T) {
	code := `
def collectRows() {
    def stream = query.getResultStream()
    sql.execute("INSERT INTO report (data) VALUES ('" + stream + "')")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for JPA Query.getResultStream -> sql.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test — a tainted DB read coerced through Integer.parseInt() is no
// longer SQL-injectable, so no SnkSQLQuery flow should be reported.
func TestGroovy_JdbcTemplateQueryForObject_Sanitized_NoFlow(t *testing.T) {
	code := `
def lookupLogs() {
    def raw = jdbcTemplate.queryForObject("SELECT id FROM users WHERE name = 'a'", String.class)
    def id = Integer.parseInt(raw)
    sql.execute("SELECT * FROM logs WHERE user_id = " + id)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when JdbcTemplate result is sanitized via parseInt")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Registration check — every new source ID must be present in the Groovy catalog.
func TestGroovy_DbReadSources_Registered(t *testing.T) {
	want := []string{
		"groovy.spring.jdbctemplate.queryforobject",
		"groovy.spring.jdbctemplate.queryforlist",
		"groovy.spring.jdbctemplate.queryformap",
		"groovy.spring.jdbctemplate.queryforrowset",
		"groovy.spring.jdbctemplate.queryforstream",
		"groovy.spring.jdbctemplate.query",
		"groovy.mybatis.sqlsession.selectone",
		"groovy.mybatis.sqlsession.selectlist",
		"groovy.mybatis.sqlsession.selectmap",
		"groovy.jpa.query.singleresult",
		"groovy.jpa.query.resultstream",
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
