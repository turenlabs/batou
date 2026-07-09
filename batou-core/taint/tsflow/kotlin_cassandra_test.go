package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------- CqlSession.execute (CWE-943) ----------

func TestKotlin_Cassandra_CqlSessionExecute_Injection(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession

fun getUser(session: CqlSession, input: String) {
    val cql = "SELECT * FROM users WHERE id = '" + input + "'"
    session.execute(cql)
}
`
	flows := Analyze(code, "/app/UserDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.cassandra.cqlsession.execute" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for CqlSession.execute; got flows: %+v", flows)
	}
}

// ---------- CqlSession.executeAsync (CWE-943) ----------

func TestKotlin_Cassandra_CqlSessionExecuteAsync_Injection(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession

fun deleteLogs(session: CqlSession, name: String) {
    val cql = "DELETE FROM logs WHERE name = '" + name + "'"
    session.executeAsync(cql)
}
`
	flows := Analyze(code, "/app/LogsDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.cassandra.cqlsession.executeasync" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for CqlSession.executeAsync; got flows: %+v", flows)
	}
}

// ---------- SimpleStatement.newInstance (CWE-943) ----------

func TestKotlin_Cassandra_SimpleStatementNewInstance_Injection(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.cql.SimpleStatement

fun search(session: com.datastax.oss.driver.api.core.CqlSession, query: String) {
    val stmt = SimpleStatement.newInstance("SELECT * FROM posts WHERE body LIKE '%" + query + "%'")
    session.execute(stmt)
}
`
	flows := Analyze(code, "/app/PostsDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.cassandra.simplestatement.newinstance" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for SimpleStatement.newInstance; got flows: %+v", flows)
	}
}

// ---------- SimpleStatement.builder (CWE-943) ----------

func TestKotlin_Cassandra_SimpleStatementBuilder_Injection(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.cql.SimpleStatement

fun count(input: String) {
    val builder = SimpleStatement.builder("SELECT count(*) FROM " + input)
    val stmt = builder.build()
}
`
	flows := Analyze(code, "/app/MetricsDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "kotlin.cassandra.simplestatement.builder" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for SimpleStatement.builder; got flows: %+v", flows)
	}
}

// ---------- Safe: parameterized SimpleStatement.newInstance ----------
// The first arg is hardcoded CQL with placeholders — not tainted — so no finding.
func TestKotlin_Cassandra_ParameterizedQuery_Safe(t *testing.T) {
	code := `
import com.datastax.oss.driver.api.core.CqlSession
import com.datastax.oss.driver.api.core.cql.SimpleStatement

fun getUser(session: CqlSession, userId: String) {
    val stmt = SimpleStatement.newInstance("SELECT * FROM users WHERE id = ?", userId)
    session.execute(stmt)
}
`
	flows := Analyze(code, "/app/UserDao.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.ID == "kotlin.cassandra.simplestatement.newinstance" ||
			f.Sink.ID == "kotlin.cassandra.cqlsession.execute" {
			t.Errorf("Unexpected CQL injection finding on parameterized query: %+v", f)
		}
	}
}
