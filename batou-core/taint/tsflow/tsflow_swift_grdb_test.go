package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — GRDB (groue/GRDB.swift) raw-SQL injection tests (CWE-89)
// =========================================================================
//
// GRDB is the most widely used Swift SQLite library. Its low-level fetch
// methods accept a *raw SQL string* under the `sql:` label as the second
// positional argument (the first is the `Database` connection, conventionally
// `db`):
//
//     try Row.fetchAll(db, sql: "SELECT * FROM player WHERE name = '\(name)'")
//
// Interpolating / concatenating user input into that `sql:` string is the
// canonical GRDB SQL-injection vector. The safe form keeps `sql:` constant
// with `?` placeholders and passes the user value via `arguments:`.
//
// Param name `input`/`query` triggers tsflow's isInputParamName seed path.

// Row.fetchAll(db, sql:) with tainted interpolation.
func TestSwift_GRDB_RowFetchAll_TaintedSQL(t *testing.T) {
	code := `
import GRDB

func handler(input: String) throws {
    try dbQueue.read { db in
        let rows = try Row.fetchAll(db, sql: "SELECT * FROM player WHERE name = '\(input)'")
        _ = rows
    }
}
`
	flows := Analyze(code, "/app/PlayerRepo.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> Row.fetchAll(db, sql:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Row.fetchOne(db, sql:) with tainted interpolation.
func TestSwift_GRDB_RowFetchOne_TaintedSQL(t *testing.T) {
	code := `
import GRDB

func handler(input: String) throws {
    try dbQueue.read { db in
        let row = try Row.fetchOne(db, sql: "SELECT * FROM users WHERE id = \(input)")
        _ = row
    }
}
`
	flows := Analyze(code, "/app/UserRepo.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> Row.fetchOne(db, sql:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Typed-record fetch: Player.fetchCursor(db, sql:) with tainted ORDER BY.
func TestSwift_GRDB_RecordFetchCursor_TaintedSQL(t *testing.T) {
	code := `
import GRDB

func handler(input: String) throws {
    try dbQueue.read { db in
        let cursor = try Player.fetchCursor(db, sql: "SELECT * FROM player ORDER BY \(input)")
        _ = cursor
    }
}
`
	flows := Analyze(code, "/app/SortRepo.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> Player.fetchCursor(db, sql:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Database.makeStatement(sql:) with tainted interpolation.
func TestSwift_GRDB_MakeStatement_TaintedSQL(t *testing.T) {
	code := `
import GRDB

func handler(input: String) throws {
    try dbQueue.write { db in
        let stmt = try db.makeStatement(sql: "DELETE FROM player WHERE name = '\(input)'")
        try stmt.execute()
    }
}
`
	flows := Analyze(code, "/app/DeleteRepo.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> db.makeStatement(sql:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Database.cachedStatement(sql:) with tainted interpolation.
func TestSwift_GRDB_CachedStatement_TaintedSQL(t *testing.T) {
	code := `
import GRDB

func handler(input: String) throws {
    try dbQueue.write { db in
        let stmt = try db.cachedStatement(sql: "UPDATE player SET name = '\(input)' WHERE id = 1")
        try stmt.execute()
    }
}
`
	flows := Analyze(code, "/app/UpdateRepo.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for input -> db.cachedStatement(sql:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: parameterized fetch. The `sql:` string (arg 1) is a constant with a
// `?` placeholder; the user value flows into `arguments:` (a later arg), which
// is NOT a dangerous arg for the fetch sink. No SnkSQLQuery flow should fire.
func TestSwift_GRDB_RowFetchAll_Parameterized_Safe(t *testing.T) {
	code := `
import GRDB

func handler(input: String) throws {
    try dbQueue.read { db in
        let rows = try Row.fetchAll(db, sql: "SELECT * FROM player WHERE name = ?", arguments: [input])
        _ = rows
    }
}
`
	flows := Analyze(code, "/app/SafeRepo.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "swift.grdb.fetch.sql" {
			t.Errorf("expected NO swift.grdb.fetch.sql flow for parameterized query, got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
