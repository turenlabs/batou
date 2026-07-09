package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ MySQL Connector/C++ 8.x X DevAPI injection tests
//
// The X DevAPI (<mysqlx/xdevapi.h>, namespace mysqlx) is Oracle's modern
// C++/C connector. These methods previously had no tsflow entries in
// cpp_sinks.go (mysqlx coverage was zero):
//
//   - mysqlx::Session::sql(str)       — raw SQL execution  (CWE-89)
//   - mysqlx::Collection::modify(expr)— CRUD selection expr (CWE-943)
//   - mysqlx::Collection::remove(expr)— CRUD selection expr (CWE-943)
//
// Each takes a raw SQL string / selection expression as the first argument
// and is the canonical injection point. The safe form binds placeholders:
//   sess.sql("... WHERE id = ?").bind(id).execute()
//   coll.modify("name = :n").bind("n", v).set(...).execute()
// =========================================================================

func TestCPP_MySQLX_Session_Sql_Injection(t *testing.T) {
	code := `
#include <mysqlx/xdevapi.h>
#include <string>

void lookup(const char* argv[]) {
    mysqlx::Session sess("mysqlx://root@127.0.0.1");
    std::string id = argv[1];
    std::string q = "SELECT name FROM test.c1 WHERE id = " + id;
    auto res = sess.sql(q).execute();
}
`
	flows := Analyze(code, "/app/mysqlx_sql.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> mysqlx::Session::sql")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQLX_Collection_Modify_Injection(t *testing.T) {
	code := `
#include <mysqlx/xdevapi.h>
#include <string>

void rename(const char* argv[]) {
    mysqlx::Session sess("mysqlx://root@127.0.0.1");
    mysqlx::Collection coll = sess.getSchema("test").getCollection("c1");
    std::string name = argv[1];
    std::string cond = "name = '" + name + "'";
    coll.modify(cond).set("age", 21).execute();
}
`
	flows := Analyze(code, "/app/mysqlx_modify.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL/CRUD injection flow for argv -> mysqlx::Collection::modify")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_MySQLX_Collection_Remove_Injection(t *testing.T) {
	// Receiver named "collection" so the typed mysqlx::Collection entry wins
	// over the generic file-`remove()` wildcard sink (cpp.remove) via the
	// strong-name match in matchSinkCall.
	code := `
#include <mysqlx/xdevapi.h>
#include <string>

void purge(const char* argv[]) {
    mysqlx::Session sess("mysqlx://root@127.0.0.1");
    mysqlx::Collection collection = sess.getSchema("test").getCollection("c1");
    std::string age = argv[1];
    std::string cond = "age < " + age;
    collection.remove(cond).execute();
}
`
	flows := Analyze(code, "/app/mysqlx_remove.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL/CRUD injection flow for argv -> mysqlx::Collection::remove")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a tainted value bound through a placeholder must NOT
// produce a SQL/NoSQL flow — the sql() argument is a constant string and the
// user input reaches only .bind(), which is not a sink.
func TestCPP_MySQLX_Session_Sql_BoundParam_NoFlow(t *testing.T) {
	code := `
#include <mysqlx/xdevapi.h>
#include <string>

void lookup(const char* argv[]) {
    mysqlx::Session sess("mysqlx://root@127.0.0.1");
    std::string id = argv[1];
    auto res = sess.sql("SELECT name FROM test.c1 WHERE id = ?").bind(id).execute();
}
`
	flows := Analyze(code, "/app/mysqlx_sql_bound.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow for a constant query with a bound parameter")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
