package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ SQLite numeric column-reader second-order sources (SrcDatabase)
//
// Completes the sqlite3_column_* read-source family for C++. The text and
// blob readers were already modelled (cpp.sqlite3.column_text /
// .column_blob); the numeric readers (column_int / column_int64 /
// column_double) were missing even though C already models column_int /
// column_double and the cpp.mysql.connector ResultSet getInt/getInt64/
// getDouble numeric readers establish the precedent that DB-stored numeric
// values are second-order taint sources.
//
// A value read from SQLite is attacker-controlled if an earlier write path
// stored unvalidated data; formatted back into a query string / command /
// file path it re-enters the program tainted.
//
// All fixtures wrap the read in a plain (no-parameter) function so the
// tsflow web-handler heuristic cannot auto-taint parameters — the new
// column-reader source is the only taint origin.
// =========================================================================

func TestCPP_SQLite3ColumnInt_SecondOrderSQLi(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <string>
#include <cppconn/statement.h>

void copyRow(sqlite3_stmt *stmt, sql::Statement *db) {
    int id = sqlite3_column_int(stmt, 0);
    std::string q = "DELETE FROM users WHERE id = " + std::to_string(id);
    db->execute(q);
}
`
	flows := Analyze(code, "/app/sqlite_col_int.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow: sqlite3_column_int -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SQLite3ColumnInt64_SecondOrderSQLi(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <string>
#include <cppconn/statement.h>

void mirror(sqlite3_stmt *stmt, sql::Statement *db) {
    long long v = sqlite3_column_int64(stmt, 0);
    std::string q = "UPDATE rows SET n = " + std::to_string(v) + " WHERE n = 1";
    db->execute(q);
}
`
	flows := Analyze(code, "/app/sqlite_col_int64.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow: sqlite3_column_int64 -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_SQLite3ColumnDouble_SecondOrderSQLi(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <string>
#include <cppconn/statement.h>

void copyPrice(sqlite3_stmt *stmt, sql::Statement *db) {
    double price = sqlite3_column_double(stmt, 0);
    std::string q = "UPDATE items SET price = " + std::to_string(price) + " WHERE id = 1";
    db->execute(q);
}
`
	flows := Analyze(code, "/app/sqlite_col_double.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection flow: sqlite3_column_double -> Statement::execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── Negative regression — a constant query with no DB read produces nothing ─

func TestCPP_SQLite3Column_ConstantSQL_NoFlow(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <cppconn/statement.h>

void initStats(sql::Statement *db) {
    db->execute("UPDATE stats SET total = 0 WHERE id = 1");
}
`
	flows := Analyze(code, "/app/sqlite_col_const.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect a SQL flow when no column read feeds the query")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ── Catalog wiring assertion ─────────────────────────────────────────────

func TestCPP_SQLiteColumnReaders_Registered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangCPP)
	if cat == nil {
		t.Fatal("C++ catalog not loaded")
	}
	have := map[string]bool{}
	for _, s := range cat.Sources() {
		have[s.ID] = true
	}
	expected := []string{
		"cpp.sqlite3.column_int",
		"cpp.sqlite3.column_int64",
		"cpp.sqlite3.column_double",
	}
	for _, id := range expected {
		if !have[id] {
			t.Errorf("expected source %q to be registered", id)
		}
	}
}
