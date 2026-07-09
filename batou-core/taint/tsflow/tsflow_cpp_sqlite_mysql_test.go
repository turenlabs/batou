package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ SQLite + MySQL Connector/C++ SQL injection tests (CWE-89)
//
// Adds coverage for three popular C++ database libraries that previously
// had no tsflow entries in cpp_sinks.go:
//
//   - SQLiteCpp           — SQLite::Database::exec / execAndGet / tryExec
//   - sqlite3pp           — database::execute / executef / execute_all
//   - MySQL Connector/C++ — sql::Statement::execute / executeQuery /
//                            executeUpdate (also used by MariaDB Connector/C++)
//
// Each method takes a raw SQL string as the first argument and is the
// canonical injection point. Safe usage requires bound placeholders via
// SQLite::Statement::bind() / sqlite3pp::command::bind() /
// PreparedStatement::setString(), respectively.
// =========================================================================

// ── SQLiteCpp ────────────────────────────────────────────────────────────

func TestCPP_SQLiteCpp_Database_Exec_Injection(t *testing.T) {
	code := `
#include <SQLiteCpp/SQLiteCpp.h>
#include <string>

void deleteUser(const char* argv[]) {
    SQLite::Database db("app.db", SQLite::OPEN_READWRITE);
    std::string name = argv[1];
    std::string q = "DELETE FROM users WHERE name = '" + name + "'";
    db.exec(q);
}
`
	flows := Analyze(code, "/app/sqlitecpp_exec.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> SQLite::Database::exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SQLiteCpp_Database_ExecAndGet_Injection(t *testing.T) {
	code := `
#include <SQLiteCpp/SQLiteCpp.h>
#include <string>

void countByName(const char* argv[]) {
    SQLite::Database db("app.db");
    std::string name = argv[1];
    std::string q = "SELECT count(*) FROM users WHERE name = '" + name + "'";
    auto v = db.execAndGet(q);
}
`
	flows := Analyze(code, "/app/sqlitecpp_execandget.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> SQLite::Database::execAndGet")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SQLiteCpp_Database_TryExec_Injection(t *testing.T) {
	code := `
#include <SQLiteCpp/SQLiteCpp.h>
#include <string>

void dropIfExists(const char* argv[]) {
    SQLite::Database db("app.db", SQLite::OPEN_READWRITE);
    std::string table = argv[1];
    std::string q = "DROP TABLE IF EXISTS " + table;
    int rc = db.tryExec(q);
}
`
	flows := Analyze(code, "/app/sqlitecpp_tryexec.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> SQLite::Database::tryExec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── sqlite3pp ────────────────────────────────────────────────────────────

func TestCPP_Sqlite3pp_Database_Execute_Injection(t *testing.T) {
	code := `
#include <sqlite3pp/sqlite3pp.h>
#include <string>

void insertContact(const char* argv[]) {
    sqlite3pp::database db("contacts.db");
    std::string name = argv[1];
    std::string q = "INSERT INTO contacts (name) VALUES ('" + name + "')";
    db.execute(q);
}
`
	flows := Analyze(code, "/app/sqlite3pp_execute.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> sqlite3pp::database::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Sqlite3pp_Database_Executef_Injection(t *testing.T) {
	code := `
#include <sqlite3pp/sqlite3pp.h>
#include <string>

void insertFmt(const char* argv[]) {
    sqlite3pp::database db("contacts.db");
    std::string val = argv[1];
    db.executef("INSERT INTO contacts (name) VALUES ('%s')", val.c_str());
}
`
	flows := Analyze(code, "/app/sqlite3pp_executef.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> sqlite3pp::database::executef")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Sqlite3pp_Database_ExecuteAll_Injection(t *testing.T) {
	code := `
#include <sqlite3pp/sqlite3pp.h>
#include <string>

void runScript(const char* argv[]) {
    sqlite3pp::database db("app.db");
    std::string scriptBody = argv[1];
    std::string q = "BEGIN; " + scriptBody + " COMMIT;";
    db.execute_all(q);
}
`
	flows := Analyze(code, "/app/sqlite3pp_executeall.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> sqlite3pp::database::execute_all")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── MySQL Connector/C++ (also MariaDB Connector/C++) ─────────────────────

func TestCPP_MySQLConnector_Statement_Execute_Injection(t *testing.T) {
	code := `
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <string>

void runDDL(sql::Connection* conn, const char* argv[]) {
    sql::Statement* stmt = conn->createStatement();
    std::string table = argv[1];
    std::string q = "DROP TABLE " + table;
    stmt->execute(q);
}
`
	flows := Analyze(code, "/app/mysqlcc_execute.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> sql::Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQLConnector_Statement_ExecuteQuery_Injection(t *testing.T) {
	code := `
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <string>

void lookupById(sql::Connection* conn, const char* argv[]) {
    sql::Statement* stmt = conn->createStatement();
    std::string id = argv[1];
    std::string q = "SELECT * FROM users WHERE id = " + id;
    sql::ResultSet* rs = stmt->executeQuery(q);
}
`
	flows := Analyze(code, "/app/mysqlcc_executequery.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> sql::Statement::executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQLConnector_Statement_ExecuteUpdate_Injection(t *testing.T) {
	code := `
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <string>

void renameUser(sql::Connection* conn, const char* argv[]) {
    sql::Statement* stmt = conn->createStatement();
    std::string newName = argv[1];
    std::string q = "UPDATE users SET name = '" + newName + "' WHERE id = 1";
    int rows = stmt->executeUpdate(q);
}
`
	flows := Analyze(code, "/app/mysqlcc_executeupdate.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> sql::Statement::executeUpdate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── Negative test (over-broadness regression) ────────────────────────────

// Constant SQL with no tainted input should NOT produce an SnkSQLQuery flow.
// This regresses if my new ObjectType matchers fire on every SQLite/MySQL call
// regardless of taint propagation.
func TestCPP_SQLiteCpp_Database_Exec_ConstantSQL_NoFlow(t *testing.T) {
	code := `
#include <SQLiteCpp/SQLiteCpp.h>

void initSchema() {
    SQLite::Database db("app.db", SQLite::OPEN_READWRITE);
    db.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)");
}
`
	flows := Analyze(code, "/app/sqlitecpp_const.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQL injection flow on constant SQL string")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
