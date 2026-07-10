package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Java reactive SQL drivers — SQL injection sinks (CWE-89)
// Covers: Spring R2DBC DatabaseClient, io.r2dbc.spi.Connection, Jasync-SQL.
// Mirrors the Kotlin coverage in kotlin_r2dbc_test.go for the Java side of
// the same APIs (the Java drivers are identical; only the call-site syntax
// differs).
// =========================================================================

func TestJava_ReactiveSQL_SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJava)
	if cat == nil {
		t.Fatal("Java catalog not loaded")
	}
	found := map[string]bool{}
	for _, s := range cat.Sinks() {
		if s.Category == taint.SnkSQLQuery {
			found[s.ID] = true
		}
	}
	want := []string{
		"java.r2dbc.databaseclient.sql",
		"java.r2dbc.connection.createstatement",
		"java.jasync.sendquery",
		"java.jasync.sendpreparedstatement",
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected SnkSQLQuery sink: %s", id)
		}
	}
}

// ---------- Spring R2DBC: DatabaseClient.sql() ----------

func TestJava_R2DBC_DatabaseClientSql_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

public class UserRepository {
    private DatabaseClient databaseClient;
    public Mono<Object> findByName(HttpServletRequest request) {
        String input = request.getParameter("name");
        String query = "SELECT * FROM users WHERE name = '" + input + "'";
        return databaseClient.sql(query).fetch().one();
    }
}
`
	flows := Analyze(code, "/app/UserRepository.java", rules.LangJava)
	if !findSinkID(flows, "java.r2dbc.databaseclient.sql") {
		t.Errorf("expected java.r2dbc.databaseclient.sql finding for getParameter -> DatabaseClient.sql; got flows: %+v", flows)
	}
}

// ---------- R2DBC SPI: Connection.createStatement() with tainted SQL ----------

func TestJava_R2DBC_ConnectionCreateStatement_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.Statement;

public class UserDao {
    public void run(HttpServletRequest request, Connection connection) {
        String input = request.getParameter("name");
        String sql = "SELECT * FROM users WHERE name = '" + input + "'";
        Statement stmt = connection.createStatement(sql);
        stmt.execute();
    }
}
`
	flows := Analyze(code, "/app/UserDao.java", rules.LangJava)
	if !findSinkID(flows, "java.r2dbc.connection.createstatement") {
		t.Errorf("expected java.r2dbc.connection.createstatement finding for getParameter -> Connection.createStatement; got flows: %+v", flows)
	}
}

// ---------- Jasync-SQL: Connection.sendQuery() ----------

func TestJava_Jasync_SendQuery_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.github.jasync.sql.db.Connection;

public class Lookup {
    public void lookup(HttpServletRequest request, Connection connection) {
        String input = request.getParameter("name");
        String sql = "SELECT * FROM users WHERE name = '" + input + "'";
        connection.sendQuery(sql);
    }
}
`
	flows := Analyze(code, "/app/Lookup.java", rules.LangJava)
	if !findSinkID(flows, "java.jasync.sendquery") {
		t.Errorf("expected java.jasync.sendquery finding for getParameter -> Connection.sendQuery; got flows: %+v", flows)
	}
}

// ---------- Jasync-SQL: Connection.sendPreparedStatement() with tainted SQL ----------
// The query STRING itself is tainted (not just the values list), bypassing the
// placeholder-protection guarantee. This is the typical "I parameterized but
// also concatenated" foot-gun.
func TestJava_Jasync_SendPreparedStatement_TaintedQuery(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.github.jasync.sql.db.Connection;
import java.util.Arrays;

public class Build {
    public void build(HttpServletRequest request, Connection connection) {
        String input = request.getParameter("col");
        String q = "SELECT " + input + " FROM users WHERE id = ?";
        connection.sendPreparedStatement(q, Arrays.asList(42));
    }
}
`
	flows := Analyze(code, "/app/Build.java", rules.LangJava)
	if !findSinkID(flows, "java.jasync.sendpreparedstatement") {
		t.Errorf("expected java.jasync.sendpreparedstatement finding for getParameter -> Connection.sendPreparedStatement with tainted SQL; got flows: %+v", flows)
	}
}

// ---------- Safe: parameterized R2DBC DatabaseClient.sql ----------
// SQL is a constant; user input bound via .bind() — no java.r2dbc.databaseclient.sql
// finding expected. Note that this test does NOT assert "zero flows" — the user
// input still flows through .bind() and may be recorded by tsflow as a
// generic taint sink (the value-binding side is not modelled as safe here);
// what matters is that the sql() call itself, with a constant string, is not
// flagged as the SQL-injection sink.
func TestJava_R2DBC_DatabaseClientSql_Parameterized_Safe(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Mono;

public class SafeRepo {
    private DatabaseClient databaseClient;
    public Mono<Object> findSafe(HttpServletRequest request) {
        String input = request.getParameter("name");
        return databaseClient.sql("SELECT * FROM users WHERE name = :name")
            .bind("name", input)
            .fetch().one();
    }
}
`
	flows := Analyze(code, "/app/SafeRepo.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.ID == "java.r2dbc.databaseclient.sql" {
			t.Errorf("Unexpected SQL injection finding on parameterized DatabaseClient.sql: %+v", f)
		}
	}
}

// ---------- Safe: Jasync sendPreparedStatement with constant SQL ----------
// Constant SQL string + values list is the canonical safe usage. Should NOT
// produce a java.jasync.sendpreparedstatement finding because the SQL string
// (arg 0) is not tainted; only the values list (arg 1) carries user input,
// which is bound by the driver.
func TestJava_Jasync_SendPreparedStatement_Safe(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.github.jasync.sql.db.Connection;
import java.util.Arrays;

public class Safe {
    public void lookupSafe(HttpServletRequest request, Connection connection) {
        String input = request.getParameter("name");
        connection.sendPreparedStatement(
            "SELECT * FROM users WHERE name = ?",
            Arrays.asList(input)
        );
    }
}
`
	flows := Analyze(code, "/app/Safe.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.ID == "java.jasync.sendpreparedstatement" {
			t.Errorf("Unexpected SQL injection finding on constant-SQL sendPreparedStatement: %+v", f)
		}
	}
}
