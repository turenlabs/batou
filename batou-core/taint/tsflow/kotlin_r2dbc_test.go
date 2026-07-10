package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Kotlin reactive SQL drivers — SQL injection sinks (CWE-89)
// Covers: Spring R2DBC DatabaseClient, io.r2dbc.spi.Connection, Jasync-SQL
// =========================================================================

func TestKotlin_ReactiveSQL_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangKotlin)
	if cat == nil {
		t.Fatal("Kotlin catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sinks() {
		if s.Category == taint.SnkSQLQuery {
			found[s.ID] = true
		}
	}
	want := []string{
		"kotlin.r2dbc.databaseclient.sql",
		"kotlin.r2dbc.connection.createstatement",
		"kotlin.jasync.sendquery",
		"kotlin.jasync.sendpreparedstatement",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SnkSQLQuery sink: %s", id)
		}
	}
}

// ---------- Spring R2DBC: DatabaseClient.sql() ----------

func TestKotlin_R2DBC_DatabaseClientSql_Injection(t *testing.T) {
	code := `
import org.springframework.r2dbc.core.DatabaseClient

suspend fun findByName(databaseClient: DatabaseClient, input: String) {
    val query = "SELECT * FROM users WHERE name = '" + input + "'"
    databaseClient.sql(query).fetch().awaitOne()
}
`
	flows := Analyze(code, "/app/UserRepository.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "kotlin.r2dbc.databaseclient.sql" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SQL injection finding for DatabaseClient.sql(); got flows: %+v", flows)
	}
}

func TestKotlin_R2DBC_DatabaseClientSql_FStyleInterpolation(t *testing.T) {
	code := `
import org.springframework.r2dbc.core.DatabaseClient

suspend fun getUser(databaseClient: DatabaseClient, query: String) {
    val cql = "SELECT * FROM users WHERE name = '$query'"
    databaseClient.sql(cql).fetch().awaitOne()
}
`
	flows := Analyze(code, "/app/UserController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "kotlin.r2dbc.databaseclient.sql" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SQL injection finding for DatabaseClient.sql() with string interpolation; got flows: %+v", flows)
	}
}

// ---------- R2DBC SPI: Connection.createStatement() ----------

func TestKotlin_R2DBC_ConnectionCreateStatement_Injection(t *testing.T) {
	code := `
import io.r2dbc.spi.Connection

suspend fun run(connection: Connection, input: String) {
    val stmt = connection.createStatement("SELECT * FROM users WHERE name = '" + input + "'")
    stmt.execute()
}
`
	flows := Analyze(code, "/app/UserDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "kotlin.r2dbc.connection.createstatement" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SQL injection finding for R2DBC Connection.createStatement(); got flows: %+v", flows)
	}
}

// ---------- Jasync-SQL: Connection.sendQuery() ----------

func TestKotlin_Jasync_SendQuery_Injection(t *testing.T) {
	code := `
import com.github.jasync.sql.db.Connection

suspend fun lookup(connection: Connection, input: String) {
    val result = connection.sendQuery("SELECT * FROM users WHERE name = '" + input + "'").await()
}
`
	flows := Analyze(code, "/app/Lookup.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "kotlin.jasync.sendquery" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SQL injection finding for Jasync sendQuery(); got flows: %+v", flows)
	}
}

// ---------- Jasync-SQL: Connection.sendPreparedStatement() with tainted SQL ----------

func TestKotlin_Jasync_SendPreparedStatement_TaintedQuery(t *testing.T) {
	code := `
import com.github.jasync.sql.db.Connection

suspend fun build(connection: Connection, input: String) {
    val q = "SELECT " + input + " FROM users WHERE id = ?"
    connection.sendPreparedStatement(q, listOf(42))
}
`
	flows := Analyze(code, "/app/Build.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "kotlin.jasync.sendpreparedstatement" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected SQL injection finding for Jasync sendPreparedStatement() with tainted SQL; got flows: %+v", flows)
	}
}

// ---------- Safe: parameterized R2DBC DatabaseClient.sql ----------
// SQL is a constant; user input bound via .bind() — no finding expected.
func TestKotlin_R2DBC_DatabaseClientSql_Parameterized_Safe(t *testing.T) {
	code := `
import org.springframework.r2dbc.core.DatabaseClient

suspend fun findSafe(databaseClient: DatabaseClient, input: String) {
    databaseClient.sql("SELECT * FROM users WHERE name = :name")
        .bind("name", input)
        .fetch().awaitOne()
}
`
	flows := Analyze(code, "/app/SafeRepo.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.ID == "kotlin.r2dbc.databaseclient.sql" {
			t.Errorf("Unexpected SQL injection finding on parameterized DatabaseClient.sql: %+v", f)
		}
	}
}

// ---------- Safe: Jasync sendPreparedStatement with constant SQL + values list ----------
func TestKotlin_Jasync_SendPreparedStatement_Safe(t *testing.T) {
	code := `
import com.github.jasync.sql.db.Connection

suspend fun lookupSafe(connection: Connection, input: String) {
    connection.sendPreparedStatement(
        "SELECT * FROM users WHERE name = ?",
        listOf(input)
    ).await()
}
`
	flows := Analyze(code, "/app/Safe.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.ID == "kotlin.jasync.sendpreparedstatement" {
			t.Errorf("Unexpected SQL injection finding on constant-SQL sendPreparedStatement: %+v", f)
		}
	}
}
