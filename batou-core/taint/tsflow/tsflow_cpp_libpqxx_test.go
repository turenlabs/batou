package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C++ libpqxx SQL injection tests (CWE-89)
// libpqxx is the official C++ binding for PostgreSQL. Non-parameterized
// query methods (exec0, exec1, exec_n, query_value, query1, query01)
// are vulnerable to SQL injection when user input is concatenated into
// the query string.
// =========================================================================

func TestCPP_Libpqxx_Exec0_Injection(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void handler(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string name = argv[1];
    std::string q = "DELETE FROM users WHERE name = '" + name + "'";
    txn.exec0(q);
}
`
	flows := Analyze(code, "/app/pqxx_exec0.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> txn.exec0")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libpqxx_Exec1_Injection(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void lookup(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string id = argv[1];
    std::string q = "SELECT * FROM users WHERE id = " + id;
    auto row = txn.exec1(q);
}
`
	flows := Analyze(code, "/app/pqxx_exec1.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> txn.exec1")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libpqxx_ExecN_Injection(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void listPage(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string orderBy = argv[1];
    std::string q = "SELECT * FROM orders ORDER BY " + orderBy;
    auto rows = txn.exec_n(10, q);
}
`
	flows := Analyze(code, "/app/pqxx_exec_n.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> txn.exec_n")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libpqxx_QueryValue_Injection(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void countFor(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string filter = argv[1];
    std::string q = "SELECT count(*) FROM events WHERE src = '" + filter + "'";
    auto v = txn.query_value(q);
}
`
	flows := Analyze(code, "/app/pqxx_query_value.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> txn.query_value")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libpqxx_Query1_Injection(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void oneRow(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string uid = argv[1];
    std::string q = "SELECT name,email FROM users WHERE id=" + uid;
    auto row = txn.query1(q);
}
`
	flows := Analyze(code, "/app/pqxx_query1.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> txn.query1")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libpqxx_Query01_Injection(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void maybeOne(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string uid = argv[1];
    std::string q = "SELECT email FROM users WHERE id=" + uid;
    auto row = txn.query01(q);
}
`
	flows := Analyze(code, "/app/pqxx_query01.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for argv -> txn.query01")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ libpqxx sanitizer tests
// esc_like() and quote_name() render user data safe for SQL. Flows that
// pass through these helpers should NOT produce SQL-injection findings.
// =========================================================================

func TestCPP_Libpqxx_EscLike_Sanitizes(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void search(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string raw = argv[1];
    std::string safe = txn.esc_like(raw);
    std::string q = "SELECT * FROM users WHERE name LIKE '%" + safe + "%'";
    txn.exec0(q);
}
`
	flows := Analyze(code, "/app/pqxx_esc_like_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL injection flow when user input passes through esc_like(); got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Libpqxx_QuoteName_Sanitizes(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void orderBy(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string col = argv[1];
    std::string safe = txn.quote_name(col);
    std::string q = "SELECT * FROM orders ORDER BY " + safe;
    txn.exec0(q);
}
`
	flows := Analyze(code, "/app/pqxx_quote_name_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL injection flow when identifier passes through quote_name(); got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// esc() is libpqxx's primary string-escaper: it renders a user-supplied
// string safe for use as a SQL string literal. Tainted input passed through
// esc() before concatenation into a query must NOT produce a SQL-injection
// finding.
func TestCPP_Libpqxx_Esc_Sanitizes(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void lookup(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string raw = argv[1];
    std::string safe = txn.esc(raw);
    std::string q = "SELECT * FROM users WHERE name = '" + safe + "'";
    txn.exec0(q);
}
`
	flows := Analyze(code, "/app/pqxx_esc_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL injection flow when user input passes through esc(); got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// quote() both escapes and quotes a user-supplied value, returning a string
// ready to drop straight into SQL. Tainted input passed through quote() must
// NOT produce a SQL-injection finding.
func TestCPP_Libpqxx_Quote_Sanitizes(t *testing.T) {
	code := `
#include <pqxx/pqxx>
#include <string>

void lookup(const char* argv[]) {
    pqxx::connection conn;
    pqxx::work txn(conn);
    std::string raw = argv[1];
    std::string safe = txn.quote(raw);
    std::string q = "SELECT * FROM users WHERE name = " + safe;
    txn.exec0(q);
}
`
	flows := Analyze(code, "/app/pqxx_quote_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL injection flow when user input passes through quote(); got %s -> %s (conf: %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
